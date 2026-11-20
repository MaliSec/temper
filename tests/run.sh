#!/usr/bin/env bash
#
# run.sh: local tests for the scripts and the build workflow. Runs
# check-policy.sh against synthetic OCI tars and checks the fail-closed
# paths of verify-build.sh and cut-registry.sh. No registry, network or keys.
#
# Usage: ./tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1" >&2; }
# expect_fail <desc> <cmd...>: command must exit non-zero
expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$desc (expected failure, got success)"; else ok "$desc"; fi
}
# expect_ok <desc> <cmd...>
expect_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc (expected success, got failure)"; fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# make_oci_tar <outfile> <run_as_uid> <file-spec...>
#   file-spec: "path mode" e.g. "usr/bin/app 0755" or "usr/bin/su 6755"
make_oci_tar() {
  # Specs: "path mode" (a file), "path ln:target" (a hard link to target in
  # the same layer); "--layer" starts the next layer.
  local out="$1" uid="$2"; shift 2
  local dir="$TMP/rootfs.$$"
  rm -rf "$dir"; mkdir -p "$dir/rootfs" "$dir/blobs/sha256"

  local spec path mode ldigest
  local ldigests=()
  seal_layer() {
    (cd "$dir/rootfs" && tar --sort=name -cf "$dir/blobs/layer.tar" .)
    ldigest=$(sha256sum "$dir/blobs/layer.tar" | cut -d' ' -f1)
    mv "$dir/blobs/layer.tar" "$dir/blobs/sha256/$ldigest"
    ldigests+=("sha256:$ldigest")
    rm -rf "$dir/rootfs"; mkdir -p "$dir/rootfs"
  }
  for spec in "$@"; do
    if [ "$spec" = --layer ]; then seal_layer; continue; fi
    path="${spec%% *}"; mode="${spec##* }"
    mkdir -p "$dir/rootfs/$(dirname "$path")"
    if [[ "$mode" == ln:* ]]; then
      ln "$dir/rootfs/${mode#ln:}" "$dir/rootfs/$path"
    else
      : > "$dir/rootfs/$path"
      chmod "$mode" "$dir/rootfs/$path"
    fi
  done
  seal_layer

  local cfg="$TMP/config.json"
  jq -n --arg uid "$uid" '{config: {User: $uid}, rootfs: {diff_ids: $ARGS.positional}}' \
    --args "${ldigests[@]}" > "$cfg"
  local cdigest
  cdigest=$(sha256sum "$cfg" | cut -d' ' -f1)
  cp "$cfg" "$dir/blobs/sha256/$cdigest"

  local man="$TMP/manifest.json"
  jq -n --arg cd "$cdigest" '{config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: ("sha256:" + $cd)}, layers: []}' > "$man"
  local mdigest
  mdigest=$(sha256sum "$man" | cut -d' ' -f1)
  cp "$man" "$dir/blobs/sha256/$mdigest"

  jq -n --arg md "$mdigest" '{manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: ("sha256:" + $md)}]}' > "$dir/index.json"
  echo '{"imageLayoutVersion":"1.0.0"}' > "$dir/oci-layout"

  (cd "$dir" && tar -cf "$out" index.json oci-layout blobs)
  rm -rf "$dir"
}

echo "== check-policy.sh: policy enforcement behavior =="
POLICY="$TMP/policy-dist"; mkdir -p "$POLICY"

make_oci_tar "$POLICY/good.tar" 65532 "usr/bin/app 0755" "etc/passwd 0644"
expect_ok "nonroot tar with no setuid passes" ./scripts/check-policy.sh "$POLICY/good.tar"

make_oci_tar "$POLICY/setuid.tar" 65532 "usr/bin/app 0755" "usr/bin/su 6755"
expect_fail "setuid file is a policy violation" ./scripts/check-policy.sh "$POLICY/setuid.tar"

make_oci_tar "$POLICY/root.tar" 0 "usr/bin/app 0755"
expect_fail "run-as root is a policy violation" ./scripts/check-policy.sh "$POLICY/root.tar"

make_oci_tar "$POLICY/apk.tar" 65532 "usr/bin/app 0755" "usr/sbin/apk 0755"
expect_fail "apk in a runtime image is a policy violation" ./scripts/check-policy.sh "$POLICY/apk.tar"

make_oci_tar "$POLICY/busybox.tar" 65532 "usr/bin/busybox 0755"
expect_fail "busybox outside base-shell is a policy violation" ./scripts/check-policy.sh "$POLICY/busybox.tar"
make_oci_tar "$POLICY/bash.tar" 65532 "usr/bin/bash 0755"
expect_fail "bash outside the shell tier is a policy violation" ./scripts/check-policy.sh "$POLICY/bash.tar"
make_oci_tar "$POLICY/sh.tar" 65532 "bin/sh 0755"
expect_fail "bin/sh outside the shell tier is a policy violation" ./scripts/check-policy.sh "$POLICY/sh.tar"
make_oci_tar "$POLICY/go-builder.tar" 65532 "usr/bin/busybox 0755"
expect_ok "builder images may carry busybox" ./scripts/check-policy.sh "$POLICY/go-builder.tar"

make_oci_tar "$POLICY/app-debug.tar" 65532 "usr/bin/busybox 0755" "usr/sbin/apk 0755"
expect_ok "debug variant may carry busybox+apk" ./scripts/check-policy.sh "$POLICY/app-debug.tar"
make_oci_tar "$POLICY/app2-debug.tar" 65532 "usr/bin/busybox 6755"
expect_fail "debug variant still rejects setuid" ./scripts/check-policy.sh "$POLICY/app2-debug.tar"

expect_fail "policy check with no tars fails closed" env OUT_DIR="$TMP/empty-dist" ./scripts/check-policy.sh
echo "not an oci tar" > "$POLICY/garbage.tar"
expect_fail "garbage tar fails (uninspectable is not a pass)" ./scripts/check-policy.sh "$POLICY/garbage.tar"

echo "== release-boundary: verify-build.sh fail-closed interfaces =="
expect_fail "verify without args fails" ./scripts/verify-build.sh
mkdir -p "$TMP/vstub"
printf '#!/bin/sh\nexit 0\n' > "$TMP/vstub/cosign"
printf '#!/bin/sh\n[ "$1" = manifest ] && echo %s\nexit 0\n' "'{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"}'" > "$TMP/vstub/crane"
chmod +x "$TMP/vstub/"*
out=$(PATH="$TMP/vstub:$PATH" COSIGN_KEY=tests/fixtures/no-such-key.pub ./scripts/verify-build.sh r/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 2>&1 || true)
grep -q 'cosign public key not found' <<<"$out" && ok "verify with a missing public key fails on the key" \
  || fail "verify with a missing public key: $out"

echo "== release-boundary: cut-registry.sh argument contracts =="
expect_fail "cut without REGISTRY fails" env DATE=2026.01.01 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
expect_fail "cut without DATE fails" env REGISTRY=reg.example IMAGE_ORG=o COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
expect_fail "key-mode cut with a missing key file fails" env REGISTRY=reg.example IMAGE_ORG=o DATE=2026.01.01 COSIGN_PRIVATE_KEY=tests/fixtures/no-such.key ./scripts/cut-registry.sh
# Outside the release workflow, a keyless cut must stop before stage 2.
for phase in "" publish finalize; do
  out=$(env -u GITHUB_ACTIONS -u COSIGN_PRIVATE_KEY \
    REGISTRY=reg.example IMAGE_ORG=o DATE=2026.01.01 ./scripts/cut-registry.sh $phase 2>&1) && rc=0 || rc=$?
  if [ "$rc" != 0 ] && ! echo "$out" | grep -q 'stage 2'; then
    ok "keyless cut (${phase:-no phase}) outside the release workflow fails before any stage runs"
  else
    fail "keyless cut (${phase:-no phase}) outside the release workflow did not fail early"
  fi
done
expect_fail "unknown cut phase fails" env REGISTRY=reg.example IMAGE_ORG=o DATE=2026.01.01 ./scripts/cut-registry.sh bogus
expect_fail "malformed DATE tag fails" env REGISTRY=reg.example IMAGE_ORG=o DATE=2026.1.1 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
expect_fail "malformed same-day suffix fails" env REGISTRY=reg.example IMAGE_ORG=o DATE=2026.01.01-1 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
for t in 2026.01.01.0 2026.01.01.01; do
  expect_fail "same-day suffix $t fails (it would tie with the plain date)" env REGISTRY=reg.example IMAGE_ORG=o DATE=$t COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
  expect_fail "rollback to $t fails" ./scripts/rollback-latest.sh $t --dry-run
done
expect_fail "build.sh --images with a filter that matches nothing fails" env OUT_DIR="$TMP/nomatch" ./scripts/build.sh --images --image nosuch-image
expect_fail "build.sh --lock with a filter that matches nothing fails" ./scripts/build.sh --lock --image nosuch-image
out=$(./scripts/rollback-latest.sh 2026.01.01 --dryrun 2>&1 || true)
grep -q '^usage: rollback-latest.sh' <<<"$out" && ok "rollback-latest refuses an unknown argument (a mistyped --dry-run never moves tags)" \
  || fail "rollback-latest accepted an unknown argument: $out"
mkdir -p "$TMP/vstub"; printf '#!/bin/sh\nexit 1\n' > "$TMP/vstub/cosign"; cp "$TMP/vstub/cosign" "$TMP/vstub/crane"; chmod +x "$TMP/vstub/"*
out=$(PATH="$TMP/vstub:$PATH" ./scripts/verify-build.sh localhost:1/o/temper/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 --date garbage 2>&1 || true)
grep -q 'is not a release tag' <<<"$out" && ok "verify-build validates --date with a digest reference" \
  || fail "verify-build accepted a malformed --date with a digest: $out"
out=$(PATH="$TMP/vstub:$PATH" ./scripts/verify-build.sh localhost:1/o/temper/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 --date 2026.01.01.0 2>&1 || true)
grep -q 'is not a release tag' <<<"$out" && ok "verify-build refuses a .0 same-day suffix" \
  || fail "verify-build accepted --date 2026.01.01.0: $out"
# An older line (a repo file) must have a version line of its own.
CUT="$TMP/cutrepo"; mkdir -p "$CUT/images"; cp -r scripts "$CUT/"; cp -r images/node "$CUT/images/node"
mkdir -p "$CUT/images/node-x"; cp images/static/apko.yaml "$CUT/images/node-x/"; echo node > "$CUT/images/node-x/repo"
echo dummy > "$TMP/dummy.key"
out=$(cd "$CUT" && env REGISTRY=localhost:1 IMAGE_ORG=o DATE="$(date -u +%Y.%m.%d)" OUT_DIR="$TMP/cutrepo-dist" \
  COSIGN_PRIVATE_KEY="$TMP/dummy.key" TEMPER_REV=unknown ./scripts/cut-registry.sh 2>&1 || true)
grep -q 'publishes to .node. as an older line but has no version line' <<<"$out" \
  && ok "the cut refuses an older-line image without a version line" \
  || fail "the cut accepted an older-line image without a version line: $(tail -2 <<<"$out")"

echo "== release workflow: SLSA Build Level 3 layout =="
RB=.github/workflows/temper-release-build.yml
job() { awk -v j="$1" '$0 ~ "^  "j":$" {f=1; next} f && /^  [a-z-]+:$/ {exit} f' "$RB"; }
# Each check below reads one job; a missing or renamed job must fail, not
# pass because the job's text is empty.
for j in build attest evidence-suites evidence-capture evidence-bundle release; do
  grep -q "^  $j:$" "$RB" || fail "release workflow has no '$j' job"
done
job build | grep -q 'id-token' \
  && fail "the build job can mint OIDC tokens (signing credentials reach build steps)" \
  || ok "the build job has no id-token permission"
job attest | grep -qE 'build\.sh|apko|melange|syft|trivy|grype' \
  && fail "the attest job runs build or scan steps" \
  || ok "the attest job runs no build or scan steps"
job evidence-capture | grep -q 'id-token' \
  && fail "the evidence capture job can mint OIDC tokens" \
  || ok "the evidence capture job has no id-token permission"
job evidence-bundle | grep -qE 'build\.sh|apko|melange|capture/run\.sh' \
  && fail "the evidence bundle job (which attests) runs build steps" \
  || ok "the evidence bundle job only packs and attests"
job release | grep -q 'needs: \[build, attest, evidence-bundle\]' \
  && ok "the release publishes tags only after the evidence bundle is attested" \
  || fail "the release job does not wait for the evidence bundle"
job attest | grep -q 'uses: actions/attest@' \
  && ok "provenance is generated by actions/attest, not by the build" \
  || fail "the attest job does not use actions/attest"
grep -rq 'slsa.dev/provenance/v0.2' scripts .github \
  && fail "a hand-written v0.2 provenance predicate remains" \
  || ok "no hand-written provenance predicate"
grep -q 'uses: ./.github/workflows/temper-release-build.yml' .github/workflows/temper-release.yml \
  && ok "temper-release.yml calls the reusable release workflow" \
  || fail "temper-release.yml does not call temper-release-build.yml"
grep -q -- '--cert-identity-regex "$CERT_IDENTITY_REGEXP"' scripts/verify-build.sh && ! grep -v '^ *#' scripts/verify-build.sh | grep -q -- '--signer-workflow' \
  && ok "verify-build pins the attestation signer to a release tag (not the workflow at any ref)" \
  || fail "verify-build does not pin the attestation signer identity"

echo "== supply chain: install-tools checksum posture =="
for var in APKO_SHA256_AMD64 APKO_SHA256_ARM64 MELANGE_SHA256_AMD64 MELANGE_SHA256_ARM64 COSIGN_SHA256_AMD64 \
           COSIGN_SHA256_ARM64 CRANE_SHA256_AMD64 CRANE_SHA256_ARM64 GRYPE_SHA256_AMD64 GRYPE_SHA256_ARM64 \
           SYFT_SHA256_AMD64 SYFT_SHA256_ARM64 TRIVY_SHA256 TRIVY_SHA256_ARM64; do
  grep -qE "^${var}=[0-9a-f]{64}" scripts/install-tools.sh \
    && ok "$var pinned (64-hex)" || fail "$var pinned checksum missing"
done
grep -v '^\s*#' scripts/install-tools.sh | grep -qE 'curl[^|]*\|\s*sh' \
  && fail "install-tools pipes curl to sh (unverified installer)" \
  || ok "no curl|sh installer in install-tools.sh"
grep -E 'curl ' scripts/install-tools.sh | grep -q 'releases/download' \
  && ok "downloads come from pinned release URLs" \
  || fail "downloads are not release-pinned"
# Pins cover Linux on amd64 and arm64; anything else has no pin and is
# refused (checked by inspection: this host cannot be another platform).
grep -q 'require_linux' scripts/install-tools.sh && grep -q 'no pinned checksum; refusing to install' scripts/install-tools.sh \
  && ok "platform gate: Linux amd64 and arm64 only, anything else refused" \
  || fail "platform gate missing"

echo "== signing contract: keyless by default, no key material in the repo =="
grep -q 'certificate-identity-regexp' scripts/verify-build.sh scripts/cut-registry.sh \
  && ok "cut and verify check the signer's workflow identity" \
  || fail "cut/verify do not check a signer identity"
grep -q 'MaliSec/temper/\\.github/workflows/temper-release' scripts/verify-build.sh \
  && ok "verify-build defaults to this project's release workflow as signer" \
  || fail "verify-build default signer is not the release workflow"
if grep -v '^\s*#' scripts/verify-build.sh | grep -q 'cosign download attestation'; then
  fail "verify-build reads unverified attestations (cosign download attestation)"
else
  ok "verify-build reads only signature-verified attestations"
fi
grep -q '^/keys/$' .gitignore && ok ".gitignore excludes /keys/" || fail ".gitignore does not exclude /keys/"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  [ -z "$(git ls-files keys)" ] && ok "no key file is tracked under keys/" || fail "a file under keys/ is tracked"
fi

echo "== hygiene: no private material committed =="
# Tracked files plus untracked files git would add (not ignored). Outside a
# git work tree there is nothing to check, which is reported, not passed.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  committable=$( { git ls-files; git ls-files --others --exclude-standard; } )
  if grep -Eq '\.(key|pem|rsa)$|melange\.rsa$|cosign\.(key)$' <<<"$committable"; then
    fail "private key material tracked or committable: $(grep -E '\.(key|pem|rsa)$|cosign\.key$' <<<"$committable" | tr '\n' ' ')"
  else
    ok "no private key material tracked or committable"
  fi
  if grep -qE '^dist/|\.tar$|^packages/[^/]+/[^/]+\.apk$' <<<"$committable"; then
    fail "build artifacts tracked or committable"
  else
    ok "no build artifacts tracked or committable"
  fi
else
  echo "  SKIP: not a git work tree; the committed-file checks need git"
fi

echo "== smoke: python runtime image =="
# Needs the image in the local daemon:
#   ./scripts/build.sh --image python && docker load < dist/python.tar
# Skipped when the image is absent. SMOKE_NO_NETWORK=1 skips the TLS check.
DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
if command -v docker >/dev/null 2>&1 && docker image inspect "python:local-$DOCKER_ARCH" >/dev/null 2>&1; then
  pyline=$(./scripts/image-line.sh python)
  cid=$(docker create -e PYTHON_LINE="$pyline" --entrypoint "/usr/bin/python$pyline" "${PYTHON_IMAGE_REF:-python:local-$DOCKER_ARCH}" /smoke.py)
  docker cp tests/smoke-python.py "$cid":/smoke.py
  if docker start -a "$cid" >/dev/null 2>&1; then
    ok "python image smoke (interpreter, stdlib, TLS, nonroot, no shell/apk/pip)"
  else
    fail "python image smoke failed (see: docker start -a <cid>)"
  fi
  docker rm "$cid" >/dev/null 2>&1 || true
else
  echo "  skip: python image not built/loaded (build.sh --image python + docker load dist/python.tar)"
fi

echo "== smoke: -fips images =="
# Needs every -fips image in the local daemon (build.sh --image '*-fips*',
# docker load); with some but not all loaded, smoke-fips.sh fails.
fips_loaded=""
if command -v docker >/dev/null 2>&1; then
  for cfg in images/*-fips*/apko.yaml; do
    n=$(basename "$(dirname "$cfg")")
    docker image inspect "$n:local-$DOCKER_ARCH" >/dev/null 2>&1 && fips_loaded="$fips_loaded $n"
  done
fi
if [ -n "$fips_loaded" ]; then
  if smoke_err=$(tests/smoke-fips.sh "$DOCKER_ARCH" 2>&1 >/dev/null); then ok "-fips smoke, every line (gofips serves, non-approved refused, local TLS with resumption, no fallback)"
  else fail "-fips smoke failed (run: tests/smoke-fips.sh $DOCKER_ARCH): $(grep -m1 -E 'Error|not loaded' <<<"$smoke_err" || tail -1 <<<"$smoke_err")"; fi
else
  echo "  skip: no -fips image built/loaded"
fi

echo "---"

# Under pipefail, "producer | grep -q" reads an early match as a miss (the
# producer dies of SIGPIPE), so the policy gate must not test file lists
# that way.
if grep -nE '"\$filelist" *\|.*grep -q' scripts/check-policy.sh >/dev/null; then
  fail "check-policy.sh pipes the file list into grep -q (fails open under pipefail)"
else
  ok "check-policy.sh tests file lists without a SIGPIPE-prone pipe"
fi
# A shell listed first in a large image (its file list is far bigger than
# a pipe buffer): the gate must still see it.
mapfile -t big < <(printf 'bin/sh 0755\n'; seq -f 'zz/f%g 0644' 1 6000)
make_oci_tar "$POLICY/bigshell.tar" 65532 "${big[@]}"
expect_fail "a shell listed first in a large image is a policy violation" ./scripts/check-policy.sh "$POLICY/bigshell.tar"
make_oci_tar "$POLICY/layer2.tar" 65532 "usr/bin/app 0755" --layer "usr/bin/su 6755"
expect_fail "a setuid file in the second layer is a policy violation" ./scripts/check-policy.sh "$POLICY/layer2.tar"
make_oci_tar "$POLICY/hardlink.tar" 65532 "usr/bin/app 0755" "usr/bin/sh ln:usr/bin/app"
expect_fail "a shell name that is a hard link is a policy violation" ./scripts/check-policy.sh "$POLICY/hardlink.tar"
make_oci_tar "$POLICY/twolayer-ok.tar" 65532 "usr/bin/app 0755" --layer "etc/app.conf 0644"
expect_ok "a clean two-layer image passes" ./scripts/check-policy.sh "$POLICY/twolayer-ok.tar"

echo "== repository layout: nested temper/<name> resolution =="
resolve_ref() { # mirrors verify-build.sh's bare-name composition
  local ref="$1" registry="$2" org="$3"
  if [[ "$ref" != *@* ]]; then
    echo "${registry}/${org}/${ref}"
  else
    echo "$ref"
  fi
}
r=$(resolve_ref "temper/static" reg.example example-org)
[ "$r" = "reg.example/example-org/temper/static" ] \
  && ok "nested temper/<name> composes under IMAGE_ORG" \
  || fail "nested name composed to: $r"
r=$(resolve_ref "static" reg.example example-org)
[ "$r" = "reg.example/example-org/static" ] \
  && ok "flat <name> still composes (compat)" \
  || fail "flat name composed to: $r"
r=$(resolve_ref "reg.example/other/name@sha256:abc" reg.example example-org)
[ "$r" = "reg.example/other/name@sha256:abc" ] \
  && ok "digest refs pass through untouched" \
  || fail "digest ref mangled: $r"

echo "== lockfile drift gate: copies the committed lockfiles before regenerating =="
# Checked on the workflow text: copying the lockfiles after the --lock run
# would compare each file to itself and never detect drift.
WF=.github/workflows/temper-build.yml
gate=$(awk '/name: Lockfile drift report$/{f=1;next} f&&/^      - name:/{exit} f' "$WF")
if echo "$gate" | awk '/cp "\$f" "lockfile-check\//{c=1} /build.sh --lock/{exit !c} END{if(!c) exit 1}'; then
  ok "drift gate snapshots the committed lockfiles before regenerating"
else
  fail "drift gate copies after regeneration (it would compare a lockfile with itself)"
fi
if echo "$gate" | grep -q 'jq.*"\$f" | jq.*> /tmp/a.json' && \
   echo "$gate" | grep -q 'jq.*"lockfile-check/.*> /tmp/b.json'; then
  ok "drift gate compares fresh output against the committed snapshot"
else
  fail "drift gate compares the wrong files"
fi
if echo "$gate" | grep 'build.sh --lock' | grep -q '|| true'; then
  fail "drift gate swallows a failed lock run"
else
  ok "drift gate fails when the lock run fails"
fi
echo "$gate" | awk '/drift=0/{d=1} d&&/cp "lockfile-check\/.*" "\$f"/{r=1} END{exit !r}' \
  && ok "drift report restores the committed lockfiles before the build" \
  || fail "drift report leaves regenerated lockfiles in place for the build"
echo "$gate" | grep -q 'for f in images/\*/apko\*.lock.json' \
  && ok "drift gate covers every image lockfile" \
  || fail "drift gate does not iterate over every image lockfile"
# The compare logic, mirroring the gate. Local packages (url under packages/)
# are stripped from both sides: the drift report is about Wolfi. A rebuilt
# local package that differs from its lock entry fails the image build
# itself (apko checks the control hash), and the recipes pin their build
# toolchain so a rebuild reproduces the locked package.
SIM="$TMP/sim"; mkdir -p "$SIM"
STRIP='[.contents.packages[] | select(((.url // "") | startswith("packages/") | not) and (.architecture == "x86_64"))]'
run_gate() { # committed fresh -> exit 0 iff they match (keyring + local packages stripped)
  echo "$1" | jq -S 'del(.contents.keyring)' | jq -S "$STRIP" > "$SIM/a.json"
  echo "$2" | jq -S 'del(.contents.keyring)' | jq -S "$STRIP" > "$SIM/b.json"
  diff -q "$SIM/a.json" "$SIM/b.json" >/dev/null
}
local_pkg='{"name":"local-pkg","version":"0.1.0-r0","architecture":"x86_64","url":"packages/x86_64/APKINDEX.tar.gz","checksum":"Q1AAA="}'
wolfi_pkg='{"name":"tzdata","version":"2026f-r0","architecture":"x86_64","url":"https://packages.wolfi.dev/os/x86_64/tzdata-2026f-r0.apk","checksum":"sha256:CCC"}'
lock_clean="{\"contents\":{\"packages\":[$local_pkg,$wolfi_pkg]}}"
lock_fresh="{\"contents\":{\"packages\":[{\"name\":\"local-pkg\",\"version\":\"0.1.0-r0\",\"url\":\"packages/x86_64/APKINDEX.tar.gz\",\"checksum\":\"Q1DIFFERENTKEY=\"},$wolfi_pkg]}}"
lock_drift="{\"contents\":{\"packages\":[$local_pkg,{\"name\":\"tzdata\",\"version\":\"2026g-r0\",\"url\":\"https://packages.wolfi.dev/os/x86_64/tzdata-2026g-r0.apk\",\"checksum\":\"sha256:DDD\"}]}}"
lock_local_drift="{\"contents\":{\"packages\":[{\"name\":\"local-pkg\",\"version\":\"0.2.0-r0\",\"url\":\"packages/x86_64/APKINDEX.tar.gz\",\"checksum\":\"Q1OTHER=\"},$wolfi_pkg]}}"
run_gate "$lock_clean" "$lock_clean" && ok "drift gate logic: clean lock passes" \
  || fail "drift gate logic: clean lock failed"
run_gate "$lock_clean" "$lock_fresh" && ok "drift gate logic: per-run local re-sign does not fail the gate" \
  || fail "drift gate logic: per-run local re-sign failed the gate (local checksums not stripped)"
if run_gate "$lock_clean" "$lock_drift"; then
  fail "drift gate logic: upstream package drift passed (gate did not detect it)"
else
  ok "drift gate logic: upstream package drift fails"
fi
run_gate "$lock_clean" "$lock_local_drift" && ok "drift gate scope: @local content drift is NOT detected (upstream-only gate, documented)" \
  || fail "drift gate scope: @local package change unexpectedly failed the gate (strip filter changed?)"

echo "== latest: forward-only date-tag ordering =="
nd() { printf '%s\n' "$@" | ./scripts/newest-date-tag.sh; }
[ "$(nd 2026.11.18 2026.11.19 latest sha256-x.sig)" = 2026.11.19 ] && ok "newest date tag ignores non-date tags" || fail "newest date tag picked a non-date tag"
[ "$(nd 2026.11.19 2026.11.19.1)" = 2026.11.19.1 ] && ok "a same-day .N release is newer than the plain date" || fail "same-day .N ordering wrong"
[ "$(nd 2026.11.19.2 2026.11.19.10)" = 2026.11.19.10 ] && ok "same-day suffixes order numerically" || fail "same-day suffixes order as strings"
[ "$(nd 2026.12.01 2026.11.30.9)" = 2026.12.01 ] && ok "a later date beats an earlier date's suffix" || fail "date ordering wrong"
[ -z "$(nd latest foo)" ] && ok "no date tag: nothing printed" || fail "non-date tags produced a result"
[ "$(nd 2026.11.19 2026.11.19.0 2026.11.19.01)" = 2026.11.19 ] && ok "a .0 or zero-padded suffix is not a date tag" || fail "a .0 or .01 suffix counted as a date tag"
grep -qF "'[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[1-9]'" .github/workflows/temper-release.yml \
  && ! grep -qE "\.\[0-9\]\+'" .github/workflows/temper-release.yml \
  && ok "the release trigger refuses a .0 or zero-padded suffix" || fail "temper-release.yml trigger accepts a .0 or .01 suffix"
grep -q 'newest-date-tag.sh' scripts/cut-registry.sh && grep -q 'crane tag "$pinned" latest' scripts/cut-registry.sh \
  && ok "the release moves latest only through the forward-only check" || fail "cut-registry does not gate latest"

echo "== scans-json.sh: the release's findings match the gate's counts =="
sj="$TMP/scans"; mkdir -p "$sj/scan"
cat > "$sj/records.json" <<'EOF'
{"scan_db": "grype DB built X", "scan_db_trivy": "trivy DB built Y", "images": [
 {"name": "app", "digest": "sha256:aa", "platforms": [
  {"arch": "amd64", "digest": "sha256:a1",
   "vulns_grype": "critical=0 high=0 medium=1 low=0 negligible=1 unknown=0 kev=0",
   "vulns_trivy": "critical=0 high=0 medium=1 low=0 unknown=0"}]}]}
EOF
cat > "$sj/scan/app.amd64.grype.json" <<'EOF'
{"descriptor": {"version": "0.1"}, "matches": [
 {"vulnerability": {"id": "CVE-1", "severity": "Medium", "fix": {"versions": ["1.1"], "state": "fixed"}},
  "artifact": {"name": "pkg", "version": "1.0", "type": "apk", "purl": "pkg:apk/wolfi/pkg@1.0"}},
 {"vulnerability": {"id": "CVE-2", "severity": "Negligible", "fix": {"versions": [], "state": ""}},
  "artifact": {"name": "pkg", "version": "1.0", "type": "apk", "purl": "pkg:apk/wolfi/pkg@1.0"}}]}
EOF
cat > "$sj/scan/app.amd64.trivy.json" <<'EOF'
{"Trivy": {"Version": "0.2"}, "Results": [{"Type": "wolfi", "Vulnerabilities": [
 {"VulnerabilityID": "CVE-1", "Severity": "MEDIUM", "PkgName": "pkg", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Status": "fixed"}]}]}
EOF
if out=$(./scripts/scans-json.sh "$sj/records.json" "$sj/scan" 2026.01.01 2>/dev/null) \
   && [ "$(jq -c '[.release, .scanners.grype.version, (.images.app.platforms.amd64.grype | map(.id + ":" + .severity + ":" + .fix_state)),
                   (.images.app.platforms.amd64.trivy | map(.id + ":" + (.fixed_in | join(","))))]' <<<"$out")" \
        = '["2026.01.01","0.1",["CVE-1:medium:fixed","CVE-2:negligible:unknown"],["CVE-1:1.1"]]' ]; then
  ok "scans-json normalizes both scanners' findings, negligible included"
else fail "scans-json output is not the expected normalized findings"; fi
sed -i 's/negligible=1/negligible=0/' "$sj/records.json"
expect_fail "scans-json refuses findings that do not match the gate's counts" \
  ./scripts/scans-json.sh "$sj/records.json" "$sj/scan" 2026.01.01
grep -q 'negligible=$(gsev Negligible)' scripts/cut-registry.sh \
  && ok "the gate's grype counts include negligible findings" || fail "cut-registry's grype counts leave out negligible"

echo "== rollback-latest.sh: fail-closed interfaces =="
expect_fail "rollback without a tag fails" ./scripts/rollback-latest.sh
expect_fail "rollback with a malformed tag fails" ./scripts/rollback-latest.sh 2026.1.1
expect_fail "rollback with an unsigned manifest fails" env MANIFEST=tests/fixtures/no-such-manifest.yaml ./scripts/rollback-latest.sh 2026.01.01 --dry-run

echo "== version drift: docs and evidence agree with the lockfiles =="
# A README that states a version for a package in its image's lockfile must
# state the pinned one. Wolfi versions look like 1.2.3-r4.
readme_bad=0
for d in images/*/; do
  img=$(basename "$d"); lock="$d/apko.lock.json"; readme="$d/README.md"
  [ -f "$lock" ] && [ -f "$readme" ] || continue
  while read -r name ver; do
    # lines that name the package and carry a Wolfi version
    lines=$(grep -E "(^|[^A-Za-z0-9_-])\`?${name//+/\\+}\`?([^A-Za-z0-9_-]|$)" "$readme" || true)
    [ -n "$lines" ] || continue
    for v in $(printf '%s\n' "$lines" | grep -oE '[0-9][0-9A-Za-z._+~]*-r[0-9]+' | sort -u || true); do
      [ "$v" = "$ver" ] || echo "$img: README states $name $v, lockfile pins $ver"
    done
  done < <(jq -r '[.contents.packages[] | select(.architecture == "x86_64") | "\(.name) \(.version)"] | unique | .[]' "$lock")
done > "$TMP/readme-drift.txt"
if [ -s "$TMP/readme-drift.txt" ]; then
  sed 's/^/    /' "$TMP/readme-drift.txt" >&2; fail "image README versions disagree with the lockfiles"
else
  ok "image README versions agree with the lockfiles"
fi

# Each lockfile records the sha256 of the config it was resolved from. For
# configs without include:, that is the file's own hash. (Debug configs
# include their base config; apko computes those.)
ck_bad=""
for cfg in images/*/apko.yaml images/*/apko.debug.yaml; do
  [ -f "$cfg" ] || continue
  grep -q '^include:' "$cfg" && continue
  lock="${cfg%.yaml}.lock.json"
  want="sha256-$(openssl dgst -sha256 -binary "$cfg" | base64 -w0)"
  [ "$(jq -r .config.checksum "$lock")" = "$want" ] || ck_bad="$ck_bad $cfg"
done
[ -z "$ck_bad" ] && ok "lockfile config checksums match their configs" \
  || fail "lockfile config checksum is stale (run: make lock IMAGE=<name>):$ck_bad"

# A -fips image is its base image plus the gofips packages and the
# environment that selects the provider (and, for node-fips, the guard):
# same packages, accounts and environment otherwise, and the same pinned
# versions.
fips_bad=""
for cfg in images/*-fips*/apko.yaml; do
  [ -f "$cfg" ] || continue
  # node-fips -> node, node-fips-24 -> node-24
  name=$(basename "$(dirname "$cfg")"); base="images/${name/-fips/}/apko.yaml"
  pkgs() { awk '/^  packages:/{f=1; next} f && /^    - /{print $2; next} f && !/^ *#/{f=0}' "$1" | grep -v '@local$' | sort; }
  block() { awk -v k="^$2:" '$0 ~ k {f=1; next} f && /^[a-z]/{f=0} f' "$1" | grep -vE '^ *#|^$|OPENSSL_CONF|GODEBUG|NODE_OPTIONS'; }
  [ "$(pkgs "$cfg")" = "$(pkgs "$base")" ] || fips_bad="$fips_bad $name:packages"
  [ "$(block "$cfg" accounts)" = "$(block "$base" accounts)" ] || fips_bad="$fips_bad $name:accounts"
  [ "$(block "$cfg" environment)" = "$(block "$base" environment)" ] || fips_bad="$fips_bad $name:environment"
  grep -q '^  OPENSSL_CONF: /etc/ssl/openssl-gofips.cnf$' "$cfg" || fips_bad="$fips_bad $name:OPENSSL_CONF"
  grep -q '^  GODEBUG: fips140=on$' "$cfg" || fips_bad="$fips_bad $name:GODEBUG"
  grep -q '^    - temper-gofips@local$' "$cfg" || fips_bad="$fips_bad $name:temper-gofips"
  if [[ "$name" == node-fips* ]]; then
    grep -q '^  NODE_OPTIONS: --require=/usr/lib/node-fips/guard.js --tls-cipher-list=' "$cfg" && grep -q '^    - temper-node-fips@local$' "$cfg" \
      || fips_bad="$fips_bad $name:node-guard"
  fi
  if [[ "$name" == python-fips* ]]; then
    pyl=$(./scripts/image-line.sh "$name")
    [ -n "$pyl" ] && grep -q "^    - temper-python-$pyl-fips@local\$" "$cfg" && [ -d "packages/python-fips-$pyl" ] \
      && [ "$(grep -c -- '-fips@local$' "$cfg")" = 1 ] || fips_bad="$fips_bad $name:python-fips-package"
  fi
  pins() { jq -r '[.contents.packages[] | select((.url // "") | startswith("packages/") | not) | "\(.architecture) \(.name) \(.version)"] | sort | .[]' "$1"; }
  [ "$(pins "${cfg%.yaml}.lock.json")" = "$(pins "${base%.yaml}.lock.json")" ] || fips_bad="$fips_bad $name:lock"
done
[ -z "$fips_bad" ] && ok "-fips images match their base images (packages, accounts, environment, pins)" \
  || fail "-fips image differs from its base (relock: make lock IMAGE=<base image>):$fips_bad"

# The shipped gofips config must be the one the evidence was captured with.
strip_cnf() { grep -vE '^\s*(#|$)' "$1" | sed 's|GOFIPS_MODULE_PATH|/usr/lib/ossl-modules/gofips.so|'; }
[ "$(strip_cnf providers/gofips/openssl-gofips.cnf)" = "$(strip_cnf providers/gofips/testdata/node-integration/openssl-gofips.cnf)" ] \
  && ok "shipped openssl-gofips.cnf matches the tested config" \
  || fail "providers/gofips/openssl-gofips.cnf differs from testdata/node-integration/openssl-gofips.cnf"

# Version-line tags: the line each image gets, and how the release uses it.
lines_bad=""
for pair in node=26 node-fips=26 node-builder=26 node-debug=26 node-24=24 node-fips-24=24 node-builder-24=24 \
            python=3.14 python-fips=3.14 python-3.13=3.13 python-fips-3.13=3.13 go-builder=1.26 static= base-glibc= git=; do
  got=$(./scripts/image-line.sh "${pair%%=*}" 2>/dev/null || echo ERR)
  [ "$got" = "${pair#*=}" ] || lines_bad="$lines_bad ${pair%%=*}:$got"
done
[ -z "$lines_bad" ] && ok "image-line.sh derives each image's version line from its package stream" \
  || fail "image-line.sh lines:$lines_bad"
# Every image ships both architectures; a config build.sh would skip for
# one of them (an arch spelling it does not recognize, a missing entry) fails.
arch_bad=""
for cfg in images/*/apko.yaml; do
  got=$(ARCHS=x86_64,aarch64 bash -c 'source <(sed -n "/^cfg_archs()/,/^}/p" scripts/build.sh); cfg_archs "$1"' _ "$cfg")
  [ "$got" = "x86_64,aarch64" ] || arch_bad="$arch_bad $cfg:[$got]"
done
[ -z "$arch_bad" ] && ok "every image config builds for x86_64 and aarch64" \
  || fail "image configs not built for both architectures:$arch_bad"

readme_bad=""
for d in images/*/; do
  # An older line (images/node-24, repo file "node") is documented in its
  # repository's README.
  n=$(basename "$d"); l=$(./scripts/image-line.sh "$n")
  r=$(if [ -f "$d/repo" ]; then tr -d '[:space:]' < "$d/repo"; else echo "$n"; fi)
  if [ -n "$l" ]; then
    grep -qF "\`$r:$l\` follows the newest release on the $l line" "images/$r/README.md" || readme_bad="$readme_bad $n"
  else
    ! grep -q '^## Tags' "$d/README.md" || readme_bad="$readme_bad $n"
  fi
done
# A repo file names a primary image directory, and every line of a
# repository is distinct (two lines must never share a tag).
repo_bad=""
for f in images/*/repo; do
  [ -f "$f" ] || continue
  n=$(basename "$(dirname "$f")"); r=$(tr -d '[:space:]' < "$f")
  [ -f "images/$r/apko.yaml" ] && [ ! -f "images/$r/repo" ] || repo_bad="$repo_bad $n:no-primary-$r"
  [ -n "$(./scripts/image-line.sh "$n")" ] || repo_bad="$repo_bad $n:no-line"
done
dups=$(for d in images/*/; do n=$(basename "$d"); r=$(if [ -f "$d/repo" ]; then tr -d '[:space:]' < "$d/repo"; else echo "$n"; fi)
  echo "$r:$(./scripts/image-line.sh "$n")"; done | sort | uniq -d | tr '\n' ' ')
[ -z "$repo_bad$dups" ] && ok "older version lines publish to an existing primary repository, one tag per line" \
  || fail "image repo files:$repo_bad duplicate lines: $dups"
[ -z "$readme_bad" ] && ok "image README Tags sections name the image's current line" \
  || fail "README Tags section disagrees with scripts/image-line.sh:$readme_bad"
mkdir -p "$TMP/stub"
printf '#!/bin/sh\nexit 1\n' > "$TMP/stub/cosign"; cp "$TMP/stub/cosign" "$TMP/stub/crane"; chmod +x "$TMP/stub/"*
for t in latest 24; do
  out=$(PATH="$TMP/stub:$PATH" REGISTRY=r IMAGE_ORG=o ./scripts/verify-build.sh temper/node --date "$t" 2>&1 || true)
  grep -q 'is not a release tag' <<<"$out" && ok "verify-build refuses the floating tag '$t'" \
    || fail "verify-build accepted or mishandled the floating tag '$t': $out"
done
cr=scripts/cut-registry.sh
if grep -qF 'for t in $([ "$primary" = true ] && echo "$DATE") ${line:+"${line}-${DATE}"}' "$cr" \
   && grep -qF 'require_tag_absent "${REGISTRY}/${IMAGE_REPO}/${repo}:${line}-${DATE}"' "$cr" \
   && grep -qF 'crane tag "${repo}@${digest}" "$line"' "$cr" \
   && grep -qF 'for t in $([ "$primary" = true ] && echo latest) ${line:+"$line"}' scripts/rollback-latest.sh; then
  ok "releases tag <line>-<date> immutably (the date and latest on the primary line only), advance <line> forward-only, and rollback moves it"
else
  fail "line tags: immutable <line>-<date>, forward-only <line>, rollback"
fi

# A release pushes by digest and adds the date tag only after verification,
# so a failed cut leaves no tag; an existing date tag stops it.
cr=scripts/cut-registry.sh
push_line=$(grep -n 'crane copy "$STAGE/$name@$digest" "${ref}@${digest}"' "$cr" | head -1 | cut -d: -f1 || true)
verify_line=$(grep -n './scripts/verify-build.sh "$pinned"' "$cr" | head -1 | cut -d: -f1 || true)
tag_line=$(grep -n 'tag_once "$repo" "$digest" "$t"' "$cr" | head -1 | cut -d: -f1 || true)
if [ -n "$push_line" ] && [ -n "$verify_line" ] && [ -n "$tag_line" ] && [ "$verify_line" -lt "$tag_line" ] \
   && ! grep -qE 'crane (push|copy) [^|]*:\$\{DATE\}' "$cr" && [ "$(grep -c 'require_tag_absent "' "$cr")" -ge 2 ]; then
  ok "release copies each index by digest, tags the date only after verification, and refuses an existing date tag"
else
  fail "release ordering: push by digest, verify, then tag the date (and check the tag is absent)"
fi


echo "---"
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
