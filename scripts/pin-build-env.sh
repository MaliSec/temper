#!/usr/bin/env bash
# Pins each package's whole build environment in packages/*/melange.yaml: the
# packages listed there and everything they pull in, at the versions melange
# resolved. melange records the resolved environment in the package's control
# data, which the lockfiles pin by checksum. Left unpinned, a Wolfi update to
# any of them (glibc, ca-certificates) changes the package and fails every
# build against the lockfiles until the next relock.
#
#   ./scripts/pin-build-env.sh             # unpin, rebuild the packages, pin
#   ./scripts/pin-build-env.sh --from DIR  # pin from DIR/<arch>/*.apk, no build
#
# The hand-written pins are kept; only the block after the marker is rewritten.
# The scheduled relock does not change these pins. After a bump, run
# ./scripts/build.sh --lock to relock the images that use the packages.
set -euo pipefail

cd "$(dirname "$0")/.."
MARKER="      # What the packages above pull in, pinned by scripts/pin-build-env.sh."
: "${ARCHS:=x86_64,aarch64}"
from=""
case "${1:-}" in
  --from) from=${2:?--from needs a directory} ;;
  "") ;;
  *) echo "usage: $0 [--from DIR]" >&2; exit 2 ;;
esac

# rewrite <melange.yaml> <file of name=version lines>: replace the pinned block
# of the top-level environment's package list (removed if the file is empty).
rewrite() {
  awk -v marker="$MARKER" -v pins="$2" '
    function emit() { if (!done) { while ((getline p < pins) > 0) { if (!m++) print marker; print "      - " p } done = 1 } }
    /^[a-z]/ { top = $0 }
    top == "environment:" && $0 == "    packages:" { inlist = 1; print; next }
    inlist && $0 == marker { skip = 1; next }
    inlist && skip && /^      - / { next }
    inlist && /^      [-#]/ { skip = 0; print; next }
    inlist { emit(); inlist = 0 }
    { print }
    END { if (inlist) emit() }
  ' "$1" > "$1.new"
  mv -- "$1.new" "$1"
}

# env <apk>: the build environment melange recorded in the package.
env_of() {
  tar -xzOf "$1" .melange.yaml 2>/dev/null | awk '
    /^[a-z]/ { top = $0 }
    top == "environment:" && $0 == "    packages:" { f = 1; next }
    f && /^      - / { sub(/^      - /, ""); print; next }
    f { exit }'
}

# The pins written by hand: the list entries before the marker.
hand_names() {
  awk -v marker="$MARKER" '
    /^[a-z]/ { top = $0 }
    top == "environment:" && $0 == "    packages:" { f = 1; next }
    f && $0 == marker { exit }
    f && /^      - / { sub(/^      - /, ""); sub(/[=<>~].*/, ""); print; next }
    f && /^      #/ { next }
    f { exit }' "$1"
}

# pinned <melange.yaml>: the entries below the marker.
pinned() {
  awk -v marker="$MARKER" '$0 == marker { f = 1; next } f && /^      - / { sub(/^      - /, ""); print; next } f { exit }' "$1"
}

recipes=(packages/*/melange.yaml)
empty=$(mktemp) saved=$(mktemp -d)
# Until every recipe is repinned, a failure or interrupt puts the previous
# pins back (only the block below the marker; edits above it stay).
for i in "${!recipes[@]}"; do pinned "${recipes[$i]}" > "$saved/$i"; done
restore() { for i in "${!recipes[@]}"; do rewrite "${recipes[$i]}" "$saved/$i"; done; }
trap 'restore' EXIT
trap 'exit 130' INT TERM
if [ -z "$from" ]; then
  for r in "${recipes[@]}"; do rewrite "$r" "$empty"; done
  ARCHS="$ARCHS" ./scripts/build.sh --packages
  from=packages
fi

for i in "${!recipes[@]}"; do
  r=${recipes[$i]}
  name=$(awk '/^package:/{f=1} f && /^  name:/{print $2; exit}' "$r")
  ver=$(awk '/^package:/{f=1} f && /^  version:/{print $2; exit}' "$r")
  epoch=$(awk '/^package:/{f=1} f && /^  epoch:/{print $2; exit}' "$r")
  first="" envs=$(mktemp)
  for a in ${ARCHS//,/ }; do
    apk="$from/$a/$name-$ver-r$epoch.apk"
    [ -f "$apk" ] || { echo "$r: $apk not found" >&2; exit 1; }
    env_of "$apk" > "$envs.$a"
    [ -s "$envs.$a" ] || { echo "$apk: no build environment recorded" >&2; exit 1; }
    if [ -z "$first" ]; then first=$a
    elif ! cmp -s "$envs.$first" "$envs.$a"; then
      echo "$r: $first and $a resolved different build environments:" >&2
      diff "$envs.$first" "$envs.$a" >&2 || true
      exit 1
    fi
  done
  awk -F= -v hand=" $(hand_names "$r" | paste -sd' ') " 'index(hand, " " $1 " ") == 0' \
    "$envs.$first" > "$saved/new.$i"
done

for i in "${!recipes[@]}"; do
  rewrite "${recipes[$i]}" "$saved/new.$i"
  echo "${recipes[$i]}: $(wc -l < "$saved/new.$i") packages pinned"
done
trap - EXIT
