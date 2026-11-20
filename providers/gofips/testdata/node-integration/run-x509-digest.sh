#!/usr/bin/env bash
# run-x509-digest.sh - X509_digest(SHA-256) under the gofips-only config
# on the OpenSSL 4 ABI (libcrypto.so.4, OpenSSL 4.0.3 in go-builder) and
# the OpenSSL 3 ABI (3.5 compat pair).
#
# For each ABI, x509_digest_probe.c must match sha256sum of the cert's
# DER, GOFIPS_DEBUG=1 must show gofips trace lines, MD5 must be
# unfetchable and SHA256 fetchable. A no-config control shows the digest
# value itself is right.
#
# Notes:
# - The OpenSSL 4 probe builds and runs inside go-builder, because
#   libcrypto.so.4 needs glibc 2.38 and common CI hosts have 2.36.
#   Headers are copied in from the runner image or host (OpenSSL 3.0
#   headers suffice for this probe).
# - The OpenSSL 3 probe runs on the host against the compat pair.
# - Module paths in each config must be valid where the probe runs
#   (container /tmp vs. host $WORK); a mismatch is the E-27 error.
#
# Usage: ./run-x509-digest.sh [node-image] [compat-libcrypto-path]
#         [runner-image] [go-builder-image]
set -uo pipefail

DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
IMAGE="${1:-node:local-$DOCKER_ARCH}"
COMPAT_LIB="${2:-${GOFIPS_LIBCRYPTO_DIR:?pass the compat libcrypto path or set GOFIPS_LIBCRYPTO_DIR (testdata/fetch-compat-openssl3.sh)}/libcrypto.so.3}"
# Image to take OpenSSL headers from; empty = this host's
# /usr/include/openssl.
RUNNER_IMAGE="${3:-}"
GOB_IMAGE="${4:-go-builder:local-$DOCKER_ARCH}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/../.."
WORK="$(mktemp -d /tmp/gofips-x509-XXXXXX)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"; docker rm -f gofips-x509-gob >/dev/null 2>&1 || true' EXIT

FAILS=0
step() { echo; echo "=== $1 ==="; }

step "Build provider"
(cd "$PROV" && CGO_ENABLED=1 GOFIPS140=v1.0.0 \
  go build -tags gofips_debug -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$WORK/temperfips.so" .) || FAILS=$((FAILS+1))

COMPAT_DIR="$(dirname "$COMPAT_LIB")"

step "Generate probe cert (test material)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/probe-key.pem" \
  -out "$WORK/probe-cert.pem" -days 2 -subj "/CN=gofips-x509-probe" \
  -sha256 2>/dev/null || FAILS=$((FAILS+1))
openssl x509 -in "$WORK/probe-cert.pem" -outform DER -out "$WORK/probe-cert.der" \
  2>/dev/null || FAILS=$((FAILS+1))

EXPECTED=$(sha256sum "$WORK/probe-cert.der" | awk '{print $1}')
echo "pinned expected X509 sha256: $EXPECTED"

step "OpenSSL4 ABI: X509_digest through gofips (libcrypto.so.4 in go-builder)"
docker rm -f gofips-x509-gob >/dev/null 2>&1 || true
docker create --name gofips-x509-gob --entrypoint /bin/sh "$GOB_IMAGE" \
  -c "sleep 300" >/dev/null
docker start gofips-x509-gob >/dev/null

# copy OpenSSL headers, including the arch-specific opensslconf.h and
# configuration.h, into go-builder
HDR="$(mktemp -d /tmp/x509-hdr-XXXXXX)"
if [ -n "$RUNNER_IMAGE" ]; then
  docker rm -f gofips-x509-hdr >/dev/null 2>&1 || true
  docker create --name gofips-x509-hdr "$RUNNER_IMAGE" sleep 60 >/dev/null
  docker start gofips-x509-hdr >/dev/null
  docker cp gofips-x509-hdr:/usr/include/openssl "$HDR/" >/dev/null
  docker cp gofips-x509-hdr:/usr/include/$(uname -m)-linux-gnu/openssl/opensslconf.h \
    "$HDR/openssl/opensslconf.h" >/dev/null 2>&1 || true
  docker cp gofips-x509-hdr:/usr/include/$(uname -m)-linux-gnu/openssl/configuration.h \
    "$HDR/openssl/configuration.h" >/dev/null 2>&1 || true
  docker rm -f gofips-x509-hdr >/dev/null 2>&1 || true
else
  cp -rL /usr/include/openssl "$HDR/"
  for h in opensslconf.h configuration.h; do
    [ -f "/usr/include/$(uname -m)-linux-gnu/openssl/$h" ] && cp -L "/usr/include/$(uname -m)-linux-gnu/openssl/$h" "$HDR/openssl/$h"
  done
fi
docker cp "$HDR/openssl" gofips-x509-gob:/usr/include/ >/dev/null
rm -rf "$HDR"

sed "s|GOFIPS_MODULE_PATH|/tmp/temperfips.so|" \
  "$HERE/openssl-gofips.cnf" > "$WORK/openssl-gob.cnf"
docker cp "$HERE/../x509_digest_probe.c" gofips-x509-gob:/tmp/ >/dev/null
docker cp "$WORK/probe-cert.pem" gofips-x509-gob:/tmp/cert.pem >/dev/null
docker cp "$WORK/temperfips.so" gofips-x509-gob:/tmp/temperfips.so >/dev/null
docker cp "$WORK/openssl-gob.cnf" gofips-x509-gob:/tmp/openssl.cnf >/dev/null

docker exec gofips-x509-gob /bin/sh -c \
  "cd /tmp && mkdir -p lib && ln -sf /usr/lib/libcrypto.so.4 lib/libcrypto.so && \
   cc -o probe40 x509_digest_probe.c -I/usr/include -L/tmp/lib -lcrypto -ldl -Wl,-rpath,/usr/lib" \
  > "$WORK/probe40-build.out" 2>&1 || FAILS=$((FAILS+1))
grep -q "probe40" <(ls -la gofips-x509-gob:/tmp/probe40 2>/dev/null) 2>/dev/null || \
  docker exec gofips-x509-gob /bin/sh -c "test -x /tmp/probe40" || {
    echo "FAIL: probe40 build in go-builder"; cat "$WORK/probe40-build.out" | tail -4; FAILS=$((FAILS+1)); }

docker exec -e OPENSSL_CONF=/tmp/openssl.cnf -e GOFIPS_DEBUG=1 -e GODEBUG=fips140=on \
  gofips-x509-gob /tmp/probe40 /tmp/cert.pem "$EXPECTED" > "$WORK/x509-o4.out" 2>&1 \
  || FAILS=$((FAILS+1))
cat "$WORK/x509-o4.out"
grep -q "X509-DIGEST-PROBE-OK" "$WORK/x509-o4.out" || FAILS=$((FAILS+1))
GOFIPS_LINES=$(grep -c "gofips:" "$WORK/x509-o4.out" || true)
echo "gofips debug lines (OpenSSL4 ABI): $GOFIPS_LINES"
[ "$GOFIPS_LINES" -gt 0 ] || { echo "FAIL: no gofips routing evidence"; FAILS=$((FAILS+1)); }
docker rm -f gofips-x509-gob >/dev/null 2>&1 || true

step "OpenSSL3 compat ABI: X509_digest through gofips (OpenSSL 3.5 compat libcrypto)"
cc -o "$WORK/x509probe3" "$HERE/../x509_digest_probe.c" \
  -I/usr/include -L"$COMPAT_DIR" -lcrypto -ldl -Wl,-rpath,"$COMPAT_DIR" || FAILS=$((FAILS+1))
sed "s|GOFIPS_MODULE_PATH|$WORK/temperfips.so|" \
  "$HERE/openssl-gofips.cnf" > "$WORK/openssl-host.cnf"
(cd "$WORK" && GOFIPS_SO="$WORK/temperfips.so" \
  OPENSSL_CONF="$WORK/openssl-host.cnf" \
  GOFIPS_DEBUG=1 GODEBUG=fips140=on \
  "$WORK/x509probe3" "$WORK/probe-cert.pem" "$EXPECTED" > "$WORK/x509-o3.out" 2>&1) || FAILS=$((FAILS+1))
cat "$WORK/x509-o3.out"
grep -q "X509-DIGEST-PROBE-OK" "$WORK/x509-o3.out" || FAILS=$((FAILS+1))
GOFIPS_LINES3=$(grep -c "gofips:" "$WORK/x509-o3.out" || true)
echo "gofips debug lines (OpenSSL3 compat ABI): $GOFIPS_LINES3"
[ "$GOFIPS_LINES3" -gt 0 ] || { echo "FAIL: no gofips routing evidence"; FAILS=$((FAILS+1)); }

# The exclusivity checks fail here by design; only the digest line counts.
step "Control: conf unset (default provider), digest must still match"
(cd "$WORK" && "$WORK/x509probe3" "$WORK/probe-cert.pem" "$EXPECTED" > "$WORK/x509-noconf.out" 2>&1) || true
if grep -q "X509-SHA256 $EXPECTED" "$WORK/x509-noconf.out"; then
  echo "PASS: digest value identical under default provider (probe measures digest, not provider)"
else
  echo "FAIL: digest differs or probe failed under default provider"
  cat "$WORK/x509-noconf.out"
  FAILS=$((FAILS+1))
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "X509 DIGEST: ALL STAGES PASSED"
else
  echo "X509 DIGEST: $FAILS STAGE(S) FAILED"
  exit 1
fi
