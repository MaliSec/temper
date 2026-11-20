#!/usr/bin/env bash
# run-node-integration.sh - gofips Node integration in the Temper node
# image (OpenSSL 4.0.3, libcrypto.so.4) under the gofips-only
# config.
#
# Usage: ./run-node-integration.sh [node-image]
#   node-image defaults to node:local-<host arch> (loaded from dist/node.tar).
#   GOFIPS_LIBCRYPTO_DIR must name the OpenSSL 3 compat pair
#   (fetch-compat-openssl3.sh).
#
# Stages:
#   1. build the provider and a poisoned variant whose SHA-256 flips the
#      first output byte
#   2. Node gates under the gofips-only config
#   3. control with no config (MD5 available)
#   4. poisoned build: Node must return the poisoned digest, showing
#      createHash('sha256') runs the gofips code
#   5. TLS 1.3 handshake and negative gates in the image
#   6. environment negatives: missing provider, no crypto provider,
#      GODEBUG=fips140=off; Node must not boot
#   7. TLS-surface and C acceptance suites on the host
#
# Inputs are staged with `docker cp`, not bind mounts: under nested docker
# the daemon resolves mount sources in its own namespace, where the job's
# workspace and private /tmp do not exist, so mounts appear empty.
# OPENSSL_CONF/GODEBUG are set at container create; OpenSSL reads the
# config at process start, so setting process.env in JS is too late.
set -uo pipefail

DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
IMAGE="${1:-node:local-$DOCKER_ARCH}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/../.."
REPO_ROOT="$(cd "$PROV/../.." && pwd)"
WORK="$(mktemp -d /tmp/gofips-node-XXXXXX)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"; docker rm -f gofips-stage gofips-run >/dev/null 2>&1 || true' EXIT

FAILS=0
step() { echo; echo "=== $1 ==="; }

# stage_cp src...: copy inputs into the staging container at /tmp/gofips
stage_cp() {
  docker inspect gofips-stage >/dev/null 2>&1 || {
    docker rm -f gofips-stage >/dev/null 2>&1 || true
    docker create --name gofips-stage --entrypoint /usr/bin/node "$IMAGE" \
      -e "require('fs').mkdirSync('/tmp/gofips',{recursive:true}); require('http').createServer((q,s)=>s.end('ok')).listen(9)" >/dev/null
    docker start gofips-stage >/dev/null
    sleep 1
  }
  local src
  for src in "$@"; do
    docker cp "$src" gofips-stage:/tmp/gofips/ >/dev/null || return 1
  done
  return 0
}

# run_staged [ENV=V ...] -- node-args...
#   Run node in a fresh container with the staged payload in /tmp/gofips
#   and the given env.
run_staged() {
  local envs=()
  while [ "$1" != "--" ]; do envs+=(-e "$1"); shift; done
  shift
  docker rm -f gofips-run >/dev/null 2>&1 || true
  rm -rf "$WORK/payload"
  mkdir -p "$WORK/payload"
  chmod 700 "$WORK/payload"
  docker cp gofips-stage:/tmp/gofips/. "$WORK/payload/" >/dev/null || return 1
  chmod 755 "$WORK/payload"
  chmod 644 "$WORK/payload"/* 2>/dev/null || true
  docker create --name gofips-run "${envs[@]}" --entrypoint /usr/bin/node "$IMAGE" "$@" >/dev/null
  docker cp "$WORK/payload/." gofips-run:/tmp/gofips/ >/dev/null
  docker start -a gofips-run
  local rc=$?
  docker rm gofips-run >/dev/null 2>&1 || true
  return $rc
}

# --- Stage 0: extract the image's libcrypto (soname libcrypto.so.4) ---
step "Extract image libcrypto + runtime versions"
CID=$(docker create "$IMAGE" /usr/bin/node -e 0)
docker cp "$CID":/usr/lib/libcrypto.so.4 "$WORK/libcrypto.so.4"
docker rm "$CID" >/dev/null
ln -sf libcrypto.so.4 "$WORK/libcrypto.so"
docker run --rm "$IMAGE" /usr/bin/node -e \
  "console.log('node', process.version, 'openssl', process.versions.openssl)"

# --- Stage 1: build provider variants. The .so has no libcrypto
# DT_NEEDED, so the same file loads on OpenSSL 3.5.9 and 4.0.3. ---
step "Build provider variants (soname-agnostic: no libcrypto DT_NEEDED)"
(
  cd "$PROV"
  CGO_ENABLED=1 GOFIPS140=v1.0.0 \
  go build -tags gofips_debug -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$WORK/temperfips.so" .
  # poisoned variant: first SHA-256 output byte flipped
  POISON_SRC="$(mktemp -d /tmp/gofips-poison-XXXXXX)"
  cp "$PROV"/*.go "$PROV/dispatch.c" "$PROV/dispatch_abi_compat.h" "$PROV/go.mod" "$POISON_SRC/"
  rm -f "$POISON_SRC"/*_test.go
  python3 - "$POISON_SRC/provider.go" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace(
    "copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 32), sum)",
    "sum[0] ^= 0xFF // POISON experiment only\n\tcopy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 32), sum)")
open(p, "w").write(s)
PYEOF
  (cd "$POISON_SRC" && \
    CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared \
    -o "$WORK/temperfips-poison.so" .)
  rm -rf "$POISON_SRC"
)
readelf -d "$WORK/temperfips.so" | grep NEEDED
sha256sum "$WORK"/temperfips*.so

# --- Stage 2: config with the real provider ---
sed "s|GOFIPS_MODULE_PATH|/tmp/gofips/temperfips.so|" \
  "$HERE/openssl-gofips.cnf" > "$WORK/openssl.cnf"

step "Stage inputs into the test container (docker cp)"
stage_cp "$HERE"/node-gofips-test.js "$HERE"/node-default-control.js \
         "$HERE"/node-tls-handshake.js "$HERE"/node-tls-negatives.js \
         "$WORK"/openssl.cnf "$WORK"/temperfips.so "$WORK"/temperfips-poison.so || {
  echo "FAIL: staging into the test container"; exit 1; }

step "Node gates: gofips-ONLY config (default provider absent)"
run_staged OPENSSL_CONF=/tmp/gofips/openssl.cnf -- \
  /tmp/gofips/node-gofips-test.js || FAILS=$((FAILS+1))

step "Positive control: no config (default provider active, md5 available)"
run_staged OPENSSL_CONF= -- \
  /tmp/gofips/node-default-control.js || FAILS=$((FAILS+1))

step "Poison experiment: Node sha256 must come from gofips"
sed "s|GOFIPS_MODULE_PATH|/tmp/gofips/temperfips-poison.so|" \
  "$HERE/openssl-gofips.cnf" > "$WORK/openssl-poison.cnf"
stage_cp "$WORK/openssl-poison.cnf"
run_staged OPENSSL_CONF=/tmp/gofips/openssl-poison.cnf -- \
  -e "console.log(require('node:crypto').createHash('sha256').update('abc').digest('hex'))" \
  > "$WORK/poison.out" 2>&1 || true
if [ ! -s "$WORK/poison.out" ]; then
  echo "POISON-DEBUG: run_staged produced no output; retrying with visible stderr"
  run_staged OPENSSL_CONF=/tmp/gofips/openssl-poison.cnf -- \
    -e "console.log(require('node:crypto').createHash('sha256').update('abc').digest('hex'))"
fi
POISON_OUT=$(grep -oE '[0-9a-f]{64}' "$WORK/poison.out" | head -1)
echo "poisoned sha256(abc) = $POISON_OUT"
if [ -z "$POISON_OUT" ]; then
  echo "POISON-OUT-CONTENT:"
  cat "$WORK/poison.out"
fi
if [ "${POISON_OUT%%-*}" = "457816bf" ] || [[ "$POISON_OUT" == 457816bf* ]]; then
  echo "PASS: poisoned first byte (0xba^0xff=0x45) => Node sha256 executed by GOFIPS"
else
  echo "FAIL: expected poisoned first byte 45..., got $POISON_OUT"
  FAILS=$((FAILS+1))
fi

# --- Stage 3: TLS handshake + negatives in-image ---
step "TLS 1.3 handshakes in-image (gofips-only config)"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/tls-key.pem" 2>/dev/null
openssl req -new -x509 -key "$WORK/tls-key.pem" -out "$WORK/tls-cert.pem" \
  -days 2 -subj "/CN=temper-gofips-test" \
  -sha256 2>/dev/null
chmod 644 "$WORK/tls-key.pem" "$WORK/tls-cert.pem"
stage_cp "$WORK/tls-key.pem" "$WORK/tls-cert.pem"
TLS_RC=0
run_staged OPENSSL_CONF=/tmp/gofips/openssl.cnf GODEBUG=fips140=on -- \
  /tmp/gofips/node-tls-handshake.js > "$WORK/tls-handshake.out" 2>&1 || TLS_RC=$?
grep -E "^(PASS|FAIL): " "$WORK/tls-handshake.out" || true
if [ "$TLS_RC" -eq 0 ] && grep -q "TLS HANDSHAKE GATES PASSED" "$WORK/tls-handshake.out" \
   && ! grep -q "^FAIL: " "$WORK/tls-handshake.out"; then
  echo "PASS: gofips-only TLS 1.3 handshake gates passed (rc=0)"
else
  echo "FAIL: gofips-only TLS 1.3 handshake gates did not pass (rc=$TLS_RC)"
  tail -5 "$WORK/tls-handshake.out"
  FAILS=$((FAILS+1))
fi

step "TLS negative gates in-image (non-GCM surfaces must still fail closed)"
run_staged OPENSSL_CONF=/tmp/gofips/openssl.cnf GODEBUG=fips140=on -- \
  /tmp/gofips/node-tls-negatives.js > "$WORK/tls-neg.out" 2>&1 || true
if grep -q "NEGATIVE GATES: ALL PASS" "$WORK/tls-neg.out"; then
  echo "PASS: negative gates ALL PASS (unserved surfaces fail closed; baseline connects)"
else
  echo "FAIL: negative gates did not all pass:"
  grep -E "NEG-FAIL|FAIL" "$WORK/tls-neg.out" | head -4
  FAILS=$((FAILS+1))
fi

step "Environment negative: provider module missing/unloadable (Node must not boot)"
sed "s|module = /tmp/gofips/temperfips.so|module = /tmp/gofips/nonexistent.so|" \
  "$WORK/openssl.cnf" > "$WORK/openssl-missing.cnf"
stage_cp "$WORK/openssl-missing.cnf"
MISSING_RC=0
run_staged OPENSSL_CONF=/tmp/gofips/openssl-missing.cnf -- \
  -e "console.log('BOOTED-WITHOUT-PROVIDER')" >/dev/null 2>&1 || MISSING_RC=$?
if [ "$MISSING_RC" -ne 0 ]; then
  echo "PASS: Node aborted at boot without the provider (rc=$MISSING_RC: no process, no traffic)"
else
  echo "FAIL: Node BOOTED without the gofips provider, fail-closed violated"
  FAILS=$((FAILS+1))
fi

step "Environment negative: config with no crypto provider (Node must not boot)"
printf 'openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\nbase = base_sect\n[base_sect]\nactivate = 1\n' > "$WORK/openssl-none.cnf"
stage_cp "$WORK/openssl-none.cnf"
NONE_RC=0
run_staged OPENSSL_CONF=/tmp/gofips/openssl-none.cnf -- \
  -e "console.log('BOOTED-WITHOUT-ANY-PROVIDER')" >/dev/null 2>&1 || NONE_RC=$?
if [ "$NONE_RC" -ne 0 ]; then
  echo "PASS: Node aborted at boot with no crypto provider (rc=$NONE_RC)"
else
  echo "FAIL: Node BOOTED with no crypto provider"
  FAILS=$((FAILS+1))
fi

step "Environment negative: GODEBUG=fips140=off (Go runtime FIPS disabled, must fail CLOSED)"
# With Go FIPS mode off, OSSL_provider_init returns 0, so Node has no
# RAND and aborts at boot (CSPRNG assert).
OFF_RC=0
run_staged OPENSSL_CONF=/tmp/gofips/openssl.cnf GODEBUG=fips140=off -- \
  -e "console.log('BOOTED-WITH-FIPS-OFF')" >"$WORK/fips-off.log" 2>&1 || OFF_RC=$?
if [ "$OFF_RC" -ne 0 ]; then
  echo "PASS: provider init refused with fips140=off, Node cannot boot (rc=$OFF_RC), no process, no traffic"
  grep -E "REFUSED|Assertion" "$WORK/fips-off.log" | head -2 || true
else
  echo "FAIL: Node BOOTED with GODEBUG=fips140=off, exclusive-FIPS gate violated"
  FAILS=$((FAILS+1))
fi

# The image's libcrypto.so.4 needs glibc 2.38+, newer than common CI hosts,
# so the host C suites link the OpenSSL 3 compat pair (glibc 2.34) from
# GOFIPS_LIBCRYPTO_DIR. The in-image Node gates cover libcrypto.so.4.
LIBCRYPTO_DIR="${GOFIPS_LIBCRYPTO_DIR:?set GOFIPS_LIBCRYPTO_DIR (run testdata/fetch-compat-openssl3.sh <dir> first)}"

step "TLS-surface suite against the OpenSSL3 compat pair (GODEBUG=fips140=on)"
cc -o "$WORK/tlstest40" "$PROV/testdata/tls_surface_test.c" \
  $(pkg-config --cflags openssl) \
  -L"$LIBCRYPTO_DIR" -lcrypto -ldl -Wl,-rpath,"$LIBCRYPTO_DIR"
# Needs the gofips-only config: the ECDH self-derive uses the legacy ctor
# EVP_PKEY_CTX_new(pk, NULL), which the core would serve from the default
# provider if reachable, failing the op-count check. See
# legacy_ctor_boundary.c.
OPENSSL_CONF="$WORK/openssl.cnf" GOFIPS_SO="$WORK/temperfips.so" \
  GODEBUG=fips140=on "$WORK/tlstest40" || FAILS=$((FAILS+1))

step "C acceptance suite against the OpenSSL3 compat pair (GODEBUG=fips140=on)"
cc -o "$WORK/pacc40" "$PROV/testdata/provider_acceptance.c" \
  $(pkg-config --cflags openssl) \
  -L"$LIBCRYPTO_DIR" -lcrypto -ldl -Wl,-rpath,"$LIBCRYPTO_DIR"
OPENSSL_CONF="$WORK/openssl.cnf" GOFIPS_SO="$WORK/temperfips.so" \
  GODEBUG=fips140=on "$WORK/pacc40" || FAILS=$((FAILS+1))

echo
if [ "$FAILS" -eq 0 ]; then
  echo "NODE INTEGRATION: ALL STAGES PASSED"
else
  echo "NODE INTEGRATION: $FAILS STAGE(S) FAILED"
  exit 1
fi
