#!/usr/bin/env bash
#
# vex-checks.sh: run each VEX statement's behavioural check (vex/evidence/,
# tests/vex/) in every loaded image that ships its package, and compare the
# result with the statement for that package version.
#
# Fails when a statement says fixed or not_affected and its check shows the
# image vulnerable, or when a check cannot run. Warns when a statement says
# affected and its check shows the image fixed: the fix has arrived, and
# the statement needs review. Reports versions no statement covers yet.
#
# Usage: tests/vex-checks.sh <amd64|arm64>
#   Images are <name>:local-<arch>, as temper-build loads them.
set -euo pipefail
cd "$(dirname "$0")/.."

arch=${1:?usage: vex-checks.sh <amd64|arm64>}
case "$arch" in
  amd64) apk_arch=x86_64 ;;
  arm64) apk_arch=aarch64 ;;
  *) echo "vex-checks: unknown arch $arch" >&2; exit 1 ;;
esac
REGISTRY_REPO="ghcr.io/malisec/temper"
fails=0 warns=0 runs=0

# Test certificates for the TLS checks, made for this run and never kept: a
# CA, and a server certificate from it for wrong.example (ECDSA P-256, which
# the FIPS images accept). Mounted at /fixtures; each check gets the path.
fx=$(mktemp -d)
trap 'rm -rf "$fx"' EXIT
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=Temper VEX check CA" -keyout "$fx/ca.key" -out "$fx/ca.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=wrong.example" -keyout "$fx/wrong-name.key" -out "$fx/wrong-name.csr" 2>/dev/null
openssl x509 -req -in "$fx/wrong-name.csr" -CA "$fx/ca.pem" -CAkey "$fx/ca.key" -days 1 -out "$fx/wrong-name.pem" \
  -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:wrong.example" \
    "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid") 2>/dev/null
chmod 755 "$fx"; chmod 644 "$fx"/*  # the images run as a non-root user

shopt -s nullglob
for ev in vex/evidence/*.json; do
  cve=$(jq -r .vulnerability "$ev")
  check=$(jq -r .check "$ev")
  [ -f "$check" ] || { echo "FAIL $cve: no check $check"; fails=$((fails + 1)); continue; }
  while IFS=$'\t' read -r pkg _; do
    for dir in images/*/; do
      name=$(basename "$dir")
      lock="$dir/apko.lock.json"
      [ -f "$lock" ] || continue
      ver=$(jq -r --arg n "$pkg" --arg a "$apk_arch" \
        '[.contents.packages[] | select(.name == $n and .architecture == $a) | .version][0] // empty' "$lock")
      [ -n "$ver" ] || continue
      repo=$name; [ ! -f "$dir/repo" ] || repo=$(tr -d '[:space:]' < "$dir/repo")
      product="pkg:oci/$repo?repository_url=$REGISTRY_REPO/$repo"
      stated=$(jq -r --arg p "$product" --arg s "pkg:apk/wolfi/$pkg@$ver" \
        '[.statements[] | select(any(.products[]; ."@id" == $p and any(.subcomponents[]; ."@id" == $s))) | .status][0] // empty' \
        "vex/$cve.json")
      image="$name:local-$arch"
      docker image inspect "$image" >/dev/null 2>&1 \
        || { echo "FAIL $cve: $image ships $pkg $ver and is not loaded"; fails=$((fails + 1)); continue; }
      set +e
      out=$(docker run --rm --network none --platform "linux/$arch" -v "$PWD/tests/vex:/v:ro" -v "$fx:/fixtures:ro" \
        --entrypoint /usr/bin/python3 "$image" -I "/v/$(basename "$check")" /fixtures 2>&1)
      rc=$?
      set -e
      runs=$((runs + 1))
      case "$rc" in
        0) got=fixed ;;
        1) got=vulnerable ;;
        *) echo "FAIL $cve in $name ($pkg $ver): the check did not run (exit $rc): $out"; fails=$((fails + 1)); continue ;;
      esac
      if [ -z "$stated" ]; then
        echo "note $cve in $name: no statement for $pkg $ver; the check shows it $got"
      elif [ "$stated" != affected ] && [ "$got" = vulnerable ]; then
        echo "FAIL $cve in $name: the statement for $pkg $ver says $stated; the check shows it vulnerable"
        fails=$((fails + 1))
      elif [ "$stated" = affected ] && [ "$got" = fixed ]; then
        echo "::warning::$cve in $name: the statement for $pkg $ver says affected; the check shows it fixed. Review the statement."
        warns=$((warns + 1))
      else
        echo "ok   $cve in $name: $pkg $ver $stated"
      fi
    done
  done < <(jq -r '.lines | to_entries[] | [.key, .value.status] | @tsv' "$ev")
done

echo "vex-checks ($arch): $runs check(s) run, $fails failure(s), $warns warning(s)"
[ "$fails" = 0 ]
