#!/usr/bin/env bash
# run.sh: capture the gofips evidence from this tree into an output
# directory. The release workflow runs it for the evidence bundle; it is
# also runnable locally. See README.md.
# Usage: run.sh <out-dir> [work-dir]   (work-dir default: ${TMPDIR:-/tmp}/gofips-capture)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
OUTDIR="${1:?usage: run.sh <out-dir> [work-dir]}"
W="${2:-${TMPDIR:-/tmp}/gofips-capture}"
mkdir -p "$W" && W="$(cd "$W" && pwd)"
GO_TGZ_SHA256=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec   # go1.26.11.linux-amd64.tar.gz
# The matrix and arm64 containers, by digest. Debian's apt packages are not
# pinned by this; assemble.py fails if a matrix file's OpenSSL is not its
# label.
GOLANG_IMAGE=docker.io/library/golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f
UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
U=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")
say() { echo "==> $*"; }

for t in docker python3 apko; do
  command -v "$t" >/dev/null || { echo "$t required on PATH (apko: make install-tools)" >&2; exit 1; }
done
rm -rf "$W/out" "$W/out-arm64" "$W/out-parity" "$W"/matrix-*.txt "$W"/*.log
mkdir -p "$W/out" "$W/out-arm64" "$W/out-parity" "$W/shared" "$W/dist"

say "capture image"
docker build -q -t gofips-capture:local "$HERE" >/dev/null
say "node and go-builder images from the committed lockfiles"
for i in node go-builder; do
  (cd "$REPO" && OUT_DIR="$W/dist" ./scripts/build.sh --images --image "$i" --arch x86_64 >/dev/null)
  docker load -q < "$W/dist/$i.tar"
done
say "OpenSSL 3.5.9 compat pair"
[ -f "$W/compat/libcrypto.so.3" ] || bash "$REPO/providers/gofips/testdata/fetch-compat-openssl3.sh" "$W/compat" >/dev/null
say "genuine OpenSSL FIPS provider"
[ -f "$W/fips/fips.so" ] || bash "$HERE/fetch-fips-provider.sh" "$W/fips" >/dev/null
# Pulled here: a pull inside the captures would write into their output.
docker pull -q "$GOLANG_IMAGE" >/dev/null
docker pull -q "$UBUNTU_IMAGE" >/dev/null

say "captures: host suites, arm64, parity, OpenSSL 3.0.13 / 3.5.7 / 4.0.3 matrix (parallel)"
docker run --rm --network host "${U[@]}" -e SHARED="$W/shared" -v "$W/shared:$W/shared" \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$REPO:/src:ro" -v "$W/compat:/compat:ro" \
  -v "$W/out:/out" -v "$HERE/host.sh:/run.sh:ro" gofips-capture:local bash /run.sh > "$W/host.log" 2>&1 &
pids+=("$!")
docker run --rm "${U[@]}" -v "$REPO:/src:ro" -v "$W/out-arm64:/out" -v "$HERE/arm64.sh:/run.sh:ro" \
  "$GOLANG_IMAGE" bash /run.sh > "$W/arm64.log" 2>&1 &
pids+=("$!")
docker run --rm "${U[@]}" -v "$REPO:/src:ro" -v "$W/compat:/compat:ro" -v "$W/fips:/fips:ro" \
  -v "$W/out-parity:/out" -v "$HERE/parity.sh:/run.sh:ro" gofips-capture:local bash /run.sh > "$W/parity.log" 2>&1 &
pids+=("$!")
M=(-v "$REPO:/src:ro" -v "$HERE/matrix.sh:/matrix.sh:ro")
docker run --rm "${M[@]}" gofips-capture:local bash /matrix.sh > "$W/matrix-4.0.3.txt" 2>&1 &
pids+=("$!")
docker run --rm "${M[@]}" "$GOLANG_IMAGE" bash -c \
  'apt-get update -qq >/dev/null && apt-get install -y -qq libssl-dev pkg-config openssl >/dev/null 2>&1; bash /matrix.sh' \
  > "$W/matrix-3.5.7.txt" 2>&1 &
pids+=("$!")
docker run --rm "${M[@]}" -e GO_TGZ_SHA256="$GO_TGZ_SHA256" "$UBUNTU_IMAGE" bash -c '
  apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates gcc libc6-dev libssl-dev pkg-config openssl >/dev/null 2>&1
  curl -fsSL https://go.dev/dl/go1.26.11.linux-amd64.tar.gz -o /tmp/go.tgz
  echo "$GO_TGZ_SHA256  /tmp/go.tgz" | sha256sum -c - >/dev/null && tar -C /usr/local -xzf /tmp/go.tgz
  PATH=/usr/local/go/bin:$PATH bash /matrix.sh' > "$W/matrix-3.0.13.txt" 2>&1 &
pids+=("$!")
# Every capture must succeed: a failed one leaves records assemble.py
# could otherwise read as complete.
failed=0
for p in "${pids[@]}"; do wait "$p" || failed=1; done
[ "$failed" = 0 ] || { echo "a capture failed; see $W/*.log and $W/matrix-*.txt" >&2; exit 1; }

say "assemble"
python3 "$HERE/assemble.py" "$W" "$REPO" "$OUTDIR"
