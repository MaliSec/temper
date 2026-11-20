#!/usr/bin/env bash
# mode-matrix.sh - build/mode matrix and release-build trace scan.
# Regenerates mode-matrix-run.log.
#
# Matrix: the GOFIPS140=v1.0.0 build loads with fips140 unset/on/only and
# refuses with off; the plain build refuses under any GODEBUG.
# Trace scan: the release build emits no debug trace output.
set -uo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/fips" "$OUT/nofips"
cd "$REPO_DIR/providers/gofips"

echo "== build/mode matrix (provider init gate) =="
GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -trimpath -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$OUT/fips/gofips.so" . || exit 1
GOWORK=off CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$OUT/nofips/gofips.so" . || exit 1

TMPBIN="${TMPDIR:-/tmp}/modeprobe.$$"
cc -o "$TMPBIN" "$REPO_DIR/providers/gofips/testdata/modeprobe.c" \
  $(pkg-config --cflags --libs openssl) || exit 1

for kind in fips nofips; do
  dir="$OUT/$kind"
  for g in unset off on only; do
    if [ "$g" = unset ]; then
      out=$(GODEBUG= "$TMPBIN" "$dir" 2>&1)
    else
      out=$(GODEBUG="fips140=$g" "$TMPBIN" "$dir" 2>&1)
    fi
    if echo "$out" | grep -q "LOADED"; then res=loaded; else res="failed to load"; fi
    echo "$kind godebug='$g' -> LOAD: gofips provider $res"
  done
done

echo "== release-binary runtime silence scan =="
# E-33: checked at runtime, not with strings(1). dbg() adds the "gofips: "
# prefix at runtime and the linker keeps the dead format literals, so a
# binary scan proves nothing. With GOFIPS_DEBUG=1 the release build must
# emit no "gofips:" lines and the gofips_debug build must emit some.
# docclean.sh 6a/6b asserts the same property.
GOFIPS_DEBUG=1 GODEBUG=fips140=on GOFIPS_SO="$OUT/fips/gofips.so" "$TMPBIN" "$OUT/fips" >/dev/null 2> "$OUT/rel.err"
rel_n=$(grep -c "gofips:" "$OUT/rel.err" || true)
echo "release build GOFIPS_DEBUG=1 trace lines: $rel_n (expect 0)"
GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -tags gofips_debug -trimpath -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$OUT/dbg/gofips.so" . || exit 1
GOFIPS_DEBUG=1 GODEBUG=fips140=on GOFIPS_SO="$OUT/dbg/gofips.so" "$TMPBIN" "$OUT/dbg" >/dev/null 2> "$OUT/dbg.err"
dbg_n=$(grep -c "gofips:" "$OUT/dbg.err" || true)
echo "debug build GOFIPS_DEBUG=1 trace lines: $dbg_n (expect > 0)"
if [ "$rel_n" -ne 0 ] || [ "$dbg_n" -eq 0 ]; then
  echo "RELEASE-SCAN FAIL: release must be trace-silent and the debug build must not be"
  exit 1
fi
