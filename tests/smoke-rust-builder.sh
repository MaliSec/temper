#!/usr/bin/env bash
#
# smoke-rust-builder.sh: in rust-builder, offline, build a crate whose build
# script compiles C, link and run it, and check that cargo auditable recorded
# the crate list in the binary.
#
# Usage: tests/smoke-rust-builder.sh <amd64|arm64>
#   The image is rust-builder:local-<arch>, as temper-build loads it.
set -euo pipefail
cd "$(dirname "$0")/.."

arch=${1:?usage: smoke-rust-builder.sh <amd64|arm64>}
case "$arch" in
  amd64) want="x86_64 42" ;;
  arm64) want="aarch64 42" ;;
  *) echo "smoke-rust-builder: unknown arch $arch" >&2; exit 1 ;;
esac

out=$(docker run --rm --network none --platform "linux/$arch" -v "$PWD/tests/rust-builder:/t:ro" \
  "rust-builder:local-$arch" sh -euc '
    cp -r /t/hello /tmp/hello
    cd /tmp/hello
    cargo auditable build --release --offline -q
    readelf -S target/release/hello | grep -q "\.dep-v0" || { echo "no .dep-v0 section: cargo auditable recorded nothing"; exit 1; }
    ./target/release/hello')
[ "$out" = "$want" ] || { echo "FAIL rust-builder ($arch): got '$out', want '$want'"; exit 1; }
echo "ok   rust-builder ($arch): C and Rust compiled, linked and ran; the crate list is in the binary"
