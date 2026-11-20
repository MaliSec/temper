#!/usr/bin/env bash
# arm64 evidence (E-04, E-12, paramshape13 ABI 3): cross-build the provider
# and suites for aarch64 against Debian's arm64 OpenSSL, run them under
# qemu-aarch64 user-mode emulation. Runs in golang:1.26.11 (Debian, amd64);
# see run.sh. Mounts: /src the repo (read-only), /out results.
set -uo pipefail
trap 'chown -R "${HOST_UID:-0}:${HOST_GID:-0}" /out 2>/dev/null || true' EXIT
say() { echo ">>> $*" >&2; }
# A failing suite is recorded here (subshells included) and makes the
# script exit non-zero at the end; assemble.py checks every result too.
FAILED=/tmp/capture.failed; : > "$FAILED"
failed() { echo "$*" >> "$FAILED"; }
dpkg --add-architecture arm64
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
  libssl-dev:arm64 libc6:arm64 qemu-user file binutils-aarch64-linux-gnu >/dev/null 2>&1 || { echo "apt failed"; exit 1; }
rm -rf /work && cp -r /src /work && P=/work/providers/gofips && T=$P/testdata && O=/out && mkdir -p /tmp/a64
CC=aarch64-linux-gnu-gcc
OSSL_INC="-I/usr/include -I/usr/include/aarch64-linux-gnu"
OSSL_LIB="-L/usr/lib/aarch64-linux-gnu -lcrypto -ldl"
QEMU="qemu-aarch64 -L /"
{ qemu-aarch64 --version | head -1; dpkg-query -W -f='libssl3t64:arm64 ${Version}\n' 'libssl3t64:arm64' 2>/dev/null; go version; } > $O/env.txt

say "cross-build"
cd $P && GOARCH=arm64 CC=$CC CGO_ENABLED=1 GOFIPS140=v1.0.0 CGO_CFLAGS="$OSSL_INC" \
  go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/a64/gofips.so . || { echo "cross-build failed"; exit 1; }
{
  file -b /tmp/a64/gofips.so
  go version -m /tmp/a64/gofips.so | grep -E 'build\s+(GOARCH|GOFIPS140)'
  aarch64-linux-gnu-readelf -d /tmp/a64/gofips.so | grep NEEDED
  echo "libcrypto-namespaced undefined symbols: $(aarch64-linux-gnu-nm -D --undefined-only /tmp/a64/gofips.so | grep -cE ' (EVP_|OSSL_|OPENSSL_|ERR_|BN_|EC_)')"
  sha256sum /tmp/a64/gofips.so
  sha256sum /usr/lib/aarch64-linux-gnu/libcrypto.so.3
} > $O/artifact.txt

for b in provider_acceptance tls_surface_test ecboundary paramshape13; do
  $CC -o /tmp/a64/$b $T/$b.c $OSSL_INC $OSSL_LIB -lpthread || { echo "cross-compile failed: $b"; exit 1; }
done
sed "s|GOFIPS_MODULE_PATH|/tmp/a64/gofips.so|" $T/node-integration/openssl-gofips.cnf > /tmp/a64/openssl.cnf

say "acceptance (E-12)"
GOFIPS_SO=/tmp/a64/gofips.so GODEBUG=fips140=on $QEMU /tmp/a64/provider_acceptance > $O/acceptance-arm64-qemu.body 2>&1 || failed acceptance
say "TLS surface (E-04)"
OPENSSL_CONF=/tmp/a64/openssl.cnf GOFIPS_SO=/tmp/a64/gofips.so GODEBUG=fips140=on $QEMU /tmp/a64/tls_surface_test > $O/tls-surface-arm64-qemu.body 2>&1 || failed tls_surface
say "determinism: 3 runs each"
for i in 1 2 3; do
  GOFIPS_SO=/tmp/a64/gofips.so GODEBUG=fips140=on $QEMU /tmp/a64/provider_acceptance 2>&1 | sha256sum
  OPENSSL_CONF=/tmp/a64/openssl.cnf GOFIPS_SO=/tmp/a64/gofips.so GODEBUG=fips140=on $QEMU /tmp/a64/tls_surface_test 2>&1 | sha256sum
done > $O/determinism.txt
say "ecboundary x3"
for i in 1 2 3; do (cd /tmp/a64 && GODEBUG=fips140=on $QEMU /tmp/a64/ecboundary /tmp/a64 2>&1 | grep -E 'ECBOUNDARY:') || failed "ecboundary run $i"; done > $O/ecboundary.txt
say "paramshape13 (ABI 3)"
(cd /tmp/a64 && GODEBUG=fips140=on $QEMU /tmp/a64/paramshape13 /tmp/a64) > $O/paramshape13-arm64.body 2>&1 || failed paramshape13
say "done"
if [ -s "$FAILED" ]; then echo "failed suites:" >&2; cat "$FAILED" >&2; exit 1; fi

