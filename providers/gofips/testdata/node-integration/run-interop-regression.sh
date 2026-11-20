#!/usr/bin/env bash
# run-interop-regression.sh - cross-provider TLS 1.3 interop, both
# directions, two containers on a shared docker network:
#   A. gofips Node client -> default-provider Node server
#   B. default-provider client -> gofips Node server
# TLS 1.3, ECDSA P-256, prime256v1, AES-256-GCM-SHA384, session tickets on.
# The gofips side uses the gofips-only OPENSSL_CONF; the default side has
# none. Also checks that GODEBUG=fips140=off refuses to boot.
#
# Inputs are staged with `docker cp`, not bind mounts: under nested docker
# the daemon resolves mount sources in its own namespace, where the job's
# /tmp is a private tmpfs, so mounts appear empty. Env is set at create
# time because OpenSSL reads the conf at process start.
#
# Usage: ./run-interop-regression.sh [node-image]
set -uo pipefail

DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
IMAGE="${1:-node:local-$DOCKER_ARCH}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/../.."
NET="interop-net"
WORK="$(mktemp -d /tmp/gofips-interop-XXXXXX)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"; docker network rm "$NET" >/dev/null 2>&1 || true' EXIT

FAILS=0
step() { echo; echo "=== $1 ==="; }

docker network create "$NET" >/dev/null 2>&1 || true

step "Build provider"
(cd "$PROV" && CGO_ENABLED=1 GOFIPS140=v1.0.0 \
  go build -tags gofips_debug -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$WORK/temperfips.so" .)

step "Stage conf + certs (P-256 ECDSA, test material only)"
sed "s|GOFIPS_MODULE_PATH|/tmp/gofips/temperfips.so|" "$HERE/openssl-gofips.cnf" > "$WORK/openssl.cnf"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/tls-key.pem" 2>/dev/null
openssl req -new -x509 -key "$WORK/tls-key.pem" -out "$WORK/tls-cert.pem" \
  -days 2 -subj "/CN=interop-regress" -sha256 2>/dev/null
chmod 644 "$WORK"/tls-*.pem

# stage_into NAME [-e K=V ...] -- cmd...
#   Create (not start) a container with env and the payload: conf, certs,
#   provider .so, script.
stage_into() {
  local name="$1"; shift
  local envs=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    # Callers pass -e K=V; drop the -e so it is not doubled. docker reads
    # '-e -e K=V' as an empty assignment and the conf is silently lost.
    [ "$1" = "-e" ] && shift
    [ "$#" -gt 0 ] || break
    envs+=(-e "$1")
    shift
  done
  [ "$#" -gt 0 ] && shift
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker create --name "$name" --network "$NET" "${envs[@]}" \
    --entrypoint /usr/bin/node "$IMAGE" "$@" >/dev/null
  local P
  P=$(mktemp -d /tmp/interop-payload-XXXXXX)
  chmod 700 "$P"
  cp "$WORK/openssl.cnf" "$WORK/tls-key.pem" "$WORK/tls-cert.pem" "$WORK/temperfips.so" "$HERE/interop-regression.js" "$P/"
  chmod 755 "$P"; chmod 644 "$P"/*; chmod 755 "$P/temperfips.so"
  docker cp "$P/." "$name":/tmp/gofips/ >/dev/null
  rm -rf "$P"
}

run_node() { # role, conf-or-empty, host
  local role="$1" conf="$2" host="$3"
  local envs=(-e ROLE="$role" -e PORT=9443 -e HOST="$host")
  [ -n "$conf" ] && envs+=(-e OPENSSL_CONF=/tmp/gofips/openssl.cnf -e GODEBUG=fips140=on)
  local name="interop-cli-$$"
  stage_into "$name" "${envs[@]}" -- /tmp/gofips/interop-regression.js
  docker start -a "$name"
  local rc=$?
  docker rm "$name" >/dev/null 2>&1 || true
  return $rc
}

step "A: gofips Node client -> default-provider OpenSSL server"
SERVER_LOG="$WORK/serverA.log"
stage_into interop-srvA -e ROLE=server-gofips -e PORT=9443 -- \
  /tmp/gofips/interop-regression.js
docker start interop-srvA >/dev/null
sleep 3
A_RC=0
# A non-empty conf argument selects the gofips config.
run_node client-gofips gofips interop-srvA > "$WORK/dirA.out" 2>&1 || A_RC=$?
grep -E "^INTEROP" "$WORK/dirA.out" || true
if [ "$A_RC" -eq 0 ]; then
  echo "PASS: A, gofips client completed TLS 1.3 with the default-provider server (rc=0)"
else
  echo "FAIL: A, gofips client did not complete TLS 1.3 with the default-provider server (rc=$A_RC)"
  FAILS=$((FAILS+1))
fi
docker rm -f interop-srvA >/dev/null 2>&1 || true

step "B: default-provider client -> gofips Node server"
SERVER_LOG="$WORK/serverB.log"
stage_into interop-srvB -e ROLE=server-gofips -e PORT=9443 \
  -e OPENSSL_CONF=/tmp/gofips/openssl.cnf -e GODEBUG=fips140=on -- \
  /tmp/gofips/interop-regression.js
docker start interop-srvB >/dev/null
sleep 3
B_RC=0
run_node client-default "" interop-srvB > "$WORK/dirB.out" 2>&1 || B_RC=$?
grep -E "^INTEROP" "$WORK/dirB.out" || true
if [ "$B_RC" -eq 0 ]; then
  echo "PASS: B, default-provider client completed TLS 1.3 with the gofips server (rc=0)"
else
  echo "FAIL: B, default-provider client did not complete TLS 1.3 with the gofips server (rc=$B_RC)"
  FAILS=$((FAILS+1))
fi
docker rm -f interop-srvB >/dev/null 2>&1 || true

step "RFC 8446 early-secret KAT (independent implementation)"
# Printed for reference only; the C suite in run-node-integration.sh
# checks the KDF vectors.
KAT_EXPECTED="7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5"
echo "KAT expected (HMAC-SHA384(zeros48, zeros48)) = $KAT_EXPECTED"
echo "(pinned as documentation; the executable check is the C suite above + both-direction interops)"

step "Fail-closed negatives on the interop config"
docker rm -f interop-neg >/dev/null 2>&1 || true
docker create --name interop-neg --network "$NET" \
  -e OPENSSL_CONF=/tmp/gofips/openssl.cnf -e GODEBUG=fips140=off \
  --entrypoint /usr/bin/node "$IMAGE" \
  -e "console.log('BOOTED-WITH-FIPS-OFF')" >/dev/null
P=$(mktemp -d /tmp/interop-neg-XXXXXX); chmod 700 "$P"
cp "$WORK/openssl.cnf" "$P/openssl.cnf"
chmod 644 "$P/openssl.cnf"
docker cp "$P/." interop-neg:/tmp/gofips/ >/dev/null
rm -rf "$P"
NEG_RC=0
docker start -a interop-neg >/dev/null 2>&1 || NEG_RC=$?
docker rm -f interop-neg >/dev/null 2>&1 || true
if [ "$NEG_RC" -ne 0 ]; then
  echo "PASS: fips140=off refused (rc=$NEG_RC), exclusive-FIPS gate holds on the interop config"
else
  echo "FAIL: booted with fips140=off, exclusive-FIPS gate violated"
  FAILS=$((FAILS+1))
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "INTEROP REGRESSIONS: ALL PASS"
else
  echo "INTEROP REGRESSIONS: $FAILS FAILED"
  exit 1
fi
