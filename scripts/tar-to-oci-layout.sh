#!/usr/bin/env bash
#
# tar-to-oci-layout.sh: rewrite an apko image tarball (docker-archive layout:
# index.json, sha256:<hex> blobs, <hex>.tar.gz layers) as an OCI image
# layout directory, which crane push --index publishes as a multi-arch
# index. The blobs are moved, not re-encoded, so every digest is unchanged.
#
# Usage: ./scripts/tar-to-oci-layout.sh <image.tar> <output dir>
set -euo pipefail
tar_file=${1:?usage: tar-to-oci-layout.sh <image.tar> <output dir>}
out=${2:?usage: tar-to-oci-layout.sh <image.tar> <output dir>}
rm -rf "$out"
mkdir -p "$out/blobs/sha256"
tar -xf "$tar_file" -C "$out"
for f in "$out"/sha256:*; do
  mv "$f" "$out/blobs/sha256/${f##*/sha256:}"
done
for f in "$out"/*.tar.gz; do
  [ -e "$f" ] || continue
  mv "$f" "$out/blobs/sha256/$(basename "$f" .tar.gz)"
done
rm -f "$out/manifest.json"
printf '{"imageLayoutVersion":"1.0.0"}\n' > "$out/oci-layout"
# Every manifest, config and layer the index names must now be a blob.
for d in $(jq -r '.manifests[].digest' "$out/index.json"); do
  m="$out/blobs/sha256/${d#sha256:}"
  [ -f "$m" ] || { echo "missing manifest blob $d" >&2; exit 1; }
  for b in $(jq -r '.config.digest, .layers[].digest' "$m"); do
    [ -f "$out/blobs/sha256/${b#sha256:}" ] || { echo "missing blob $b (manifest $d)" >&2; exit 1; }
  done
done
