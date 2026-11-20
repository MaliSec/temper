#!/usr/bin/env bash
# run-dual-openssl.sh: dual_openssl.c (OpenSSL 3 and 4 in one process, one
# gofips.so) in the pinned Wolfi container (dual-openssl.env), with the
# config the images ship.
#
# Usage: run-dual-openssl.sh [gofips.so]
#   With a gofips.so (the release's shipped one), it is tested as given;
#   without, one is built from this tree against the OpenSSL 4.0.3 headers.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=dual-openssl.env
. "$HERE/dual-openssl.env"
SO_MOUNT=()
if [ -n "${1:-}" ]; then
  SO_MOUNT=(-v "$(cd "$(dirname "$1")" && pwd)/$(basename "$1"):/given/gofips.so:ro")
fi
docker run --rm -v "$REPO:/src:ro" "${SO_MOUNT[@]}" \
  -e WOLFI_PACKAGES="$WOLFI_PACKAGES" -e OSSL4_HEADERS="$OSSL4_HEADERS" "$WOLFI_IMAGE" sh -c '
  set -e
  apk add -q --no-cache $WOLFI_PACKAGES >/dev/null 2>&1 || { echo "apk add FAILED"; exit 1; }
  mkdir -p /tmp/m4
  if [ -f /given/gofips.so ]; then
    cp /given/gofips.so /tmp/m4/gofips.so
    echo "gofips.so: as given"
  else
    apk add -q --no-cache --root /opt/ossl4 --initdb --no-scripts --keys-dir /etc/apk/keys \
      --repositories-file /etc/apk/repositories $OSSL4_HEADERS >/dev/null 2>&1 \
      || { echo "OpenSSL 4 headers FAILED"; exit 1; }
    cp -r /src/providers/gofips /w
    (cd /w && CGO_ENABLED=1 GOFIPS140=v1.0.0 CGO_CFLAGS=-I/opt/ossl4/usr/include \
      go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/m4/gofips.so .)
    echo "gofips.so: built against the OpenSSL 4.0.3 headers"
  fi
  cc -o /tmp/dual_openssl /src/providers/gofips/testdata/dual_openssl.c -ldl -lpthread
  sed "s|/usr/lib/ossl-modules/gofips.so|/tmp/m4/gofips.so|" /src/providers/gofips/openssl-gofips.cnf > /tmp/g4.cnf
  echo "libcrypto: $(ls /usr/lib/libcrypto.so.3 /usr/lib/libcrypto.so.4 | tr "\n" " ")"
  GODEBUG=fips140=on /tmp/dual_openssl /tmp/g4.cnf'
