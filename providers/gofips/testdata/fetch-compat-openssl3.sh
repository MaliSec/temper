#!/usr/bin/env bash
# fetch-compat-openssl3.sh - obtain the OpenSSL 3.5 library pair the
# OpenSSL-3 ABI suites link against.
#
# Why a fetched pair: the Temper images ship OpenSSL 4, whose libcrypto
# needs a newer glibc than common CI hosts have, and those hosts' own
# OpenSSL is 3.0. This pair (OpenSSL 3.5.9, built against glibc 2.34) links
# on any glibc 2.34+ host and gives the suites a current OpenSSL 3 ABI.
#
# The pair is not committed. It is extracted from the Red Hat UBI 9 minimal
# base image, pinned by digest, and checked against the sha256 values below
# (also recorded in docs/audit/04-build-provenance.md).
#
# Usage: fetch-compat-openssl3.sh <output-dir>
# Then:  export GOFIPS_LIBCRYPTO_DIR=<output-dir>
set -euo pipefail
OUT="${1:?usage: fetch-compat-openssl3.sh <output-dir>}"
IMAGE="registry.access.redhat.com/ubi9/ubi-minimal@sha256:baafce2d34783a28b4a472779f304e97e00f9d35c99553bc53b068b14344d9a9"
case "$(uname -m)" in
  x86_64) PLATFORM=linux/amd64
    CRYPTO_SHA=0a19a8d0252b09c68ba1a4e8a1398248f636da837e5074529861f7b92a451280
    SSL_SHA=ce08056805f0ed2ce702254609f138f43e1819a4327c00afaec754d46e001605 ;;
  aarch64) PLATFORM=linux/arm64
    CRYPTO_SHA=09a28b8d2f7a70b462ec1a7b2ca53956c74d834879c6e62ddb1a159c54ba7f18
    SSL_SHA=b9398eca5e54975a3dbc926657cb6e0fda6d70777ed777d7e72f0d75a9bc507a ;;
  *) echo "no compat pair pinned for $(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$OUT"
docker pull -q --platform "$PLATFORM" "$IMAGE" >/dev/null
CID=$(docker create --platform "$PLATFORM" "$IMAGE" /bin/true)
trap 'docker rm "$CID" >/dev/null 2>&1 || true' EXIT
docker cp "$CID":/usr/lib64/libcrypto.so.3.5.9 "$OUT/libcrypto.so.3"
docker cp "$CID":/usr/lib64/libssl.so.3.5.9 "$OUT/libssl.so.3"
echo "$CRYPTO_SHA  $OUT/libcrypto.so.3" | sha256sum -c -
echo "$SSL_SHA  $OUT/libssl.so.3" | sha256sum -c -
echo "compat pair ready in $OUT"
