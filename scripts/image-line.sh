#!/usr/bin/env bash
#
# image-line.sh: print an image's version line (24 for nodejs-24, 3.13 for
# python-3.13, 1.26 for go-1.26, 1.100 for rust-1.100), or nothing for an
# image without one.
# images/<name>/line overrides the derived value; an empty file means none.
# A -debug variant has its base image's line.
#
# Usage: ./scripts/image-line.sh <image name>
set -euo pipefail
cd "$(dirname "$0")/.."

name=${1:?usage: image-line.sh <image name>}
name=${name%-debug}
dir="images/$name"
[ -f "$dir/apko.yaml" ] || { echo "no such image: $name" >&2; exit 1; }
if [ -f "$dir/line" ]; then
  line=$(tr -d '[:space:]' < "$dir/line")
else
  line=$(sed -nE 's/^    - (nodejs-([0-9]+)|python-([0-9]+\.[0-9]+)|go-([0-9]+\.[0-9]+)|rust-([0-9]+\.[0-9]+))$/\2\3\4\5/p' "$dir/apko.yaml" | head -1)
fi
[ -z "$line" ] || [[ "$line" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "$name: invalid line '$line'" >&2; exit 1; }
printf '%s\n' "$line"
