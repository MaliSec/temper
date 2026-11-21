#!/usr/bin/env bash
#
# smoke-fips.sh: run the -fips smoke tests in every -fips image (each version
# line), which must all be loaded, with throwaway certificates for their local TLS checks
# (the images have no tool to make one).
#
# Usage: tests/smoke-fips.sh <amd64|arm64>
set -euo pipefail
cd "$(dirname "$0")/.."
arch=${1:?usage: smoke-fips.sh <amd64|arm64>}
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
# An RSA certificate and key, which the images must refuse to serve.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$dir/rsa-key.pem" -out "$dir/rsa-cert.pem" 2>/dev/null
printf temper-fips | openssl pkeyutl -encrypt -certin -inkey "$dir/rsa-cert.pem" \
  -pkeyopt rsa_padding_mode:oaep -out "$dir/rsa-oaep.bin"
chmod 0755 "$dir"; chmod 0644 "$dir"/*
run() { docker run --rm --platform "linux/$arch" -v "$PWD/tests:/t:ro" -v "$dir:/tls:ro" -e SMOKE_NO_NETWORK "$@"; }
missing=""
for cfg in images/node-fips*/apko.yaml images/python-fips*/apko.yaml; do
  name=$(basename "$(dirname "$cfg")")
  docker image inspect "$name:local-$arch" >/dev/null 2>&1 || { missing="$missing $name:local-$arch"; continue; }
  line=$(./scripts/image-line.sh "$name")
  case "$name" in
    node-fips*) run --entrypoint /usr/bin/node "$name:local-$arch" /t/smoke-node-fips.js ;;
    python-fips*) run -e PYTHON_LINE="$line" --entrypoint "/usr/bin/python$line" "$name:local-$arch" /t/smoke-python-fips.py ;;
  esac
done
[ -z "$missing" ] || { echo "not loaded:$missing" >&2; exit 1; }

# OpenSSL 3 and 4 in one process, each with gofips as its only crypto
# provider (providers/gofips/testdata/dual_openssl.c): built in
# base-glibc-dev, then run in each node-fips image against the image's own
# libraries and config.
docker image inspect "base-glibc-dev:local-$arch" >/dev/null 2>&1 \
  || { echo "not loaded: base-glibc-dev:local-$arch (builds the dual OpenSSL check)" >&2; exit 1; }
bin=$(mktemp -d); trap 'rm -rf "$dir" "$bin"' EXIT
cp providers/gofips/testdata/dual_openssl.c "$bin/"; chmod 0777 "$bin"; chmod 0644 "$bin/dual_openssl.c"
docker run --rm --platform "linux/$arch" -v "$bin:/b" --entrypoint /bin/sh "base-glibc-dev:local-$arch" \
  -c 'cc -O2 -o /b/dual_openssl /b/dual_openssl.c -ldl -lpthread'
for cfg in images/node-fips*/apko.yaml; do
  name=$(basename "$(dirname "$cfg")")
  out=$(docker run --rm --platform "linux/$arch" -v "$bin:/b:ro" --entrypoint /b/dual_openssl \
    "$name:local-$arch" /etc/ssl/openssl-gofips.cnf 2>&1) || true
  grep -q '^DUALOPENSSL: ALL PASS' <<<"$out" \
    || { printf '%s\n' "$out" | tail -8 >&2; echo "$name: OpenSSL 3 and 4 do not both use only gofips" >&2; exit 1; }
  echo "smoke ok: $name (OpenSSL 3 and 4 in one process, both on gofips only)"
done
