#!/usr/bin/env bash
# docclean.sh - run the build/test/debug commands the docs give an
# operator, as written, in a fresh checkout, and check each does what the
# docs claim (e.g. a debug tag misspelled in the docs would silently build
# without the feature).
#
# Sources: providers/gofips/README.md, audit pages 04/08/12, debug_tag.go.
#   1. FIPS build per SP 11.1
#   2. approved-mode marker (go version -m | grep GOFIPS140)
#   3. debug build with the tag spelling the docs use (must match
#      debug_tag.go's //go:build line)
#   4. C acceptance suite compile and run
#   5. differential suite compile and run (page 12)
#   6. GOFIPS_DEBUG=1 traces: debug build emits them, release build none
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SCRATCH="$(mktemp -d /tmp/docclean.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT
FAILS=0
CHECK() { if [ "$1" -eq 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; FAILS=$((FAILS+1)); fi; }

# Fresh worktree of HEAD; fall back to a shallow clone where worktree add
# is refused (shallow CI checkouts, some containers).
export GIT_CONFIG_GLOBAL=/dev/null   # avoid dubious-ownership blocks in containers
git -C "$REPO" worktree add --detach "$SCRATCH/tree" HEAD >/dev/null 2>&1 \
  || git -c safe.directory='*' clone --depth 1 "file://$REPO" "$SCRATCH/tree" >/dev/null 2>&1 \
  || { echo "FAIL: could not create a clean checkout (worktree and clone both refused)"; exit 1; }
trap 'git -C "$REPO" worktree remove --force "$SCRATCH/tree" >/dev/null 2>&1; rm -rf "$SCRATCH"' EXIT
cd "$SCRATCH/tree"


# 1. FIPS build as on audit page 04, from the module root
cd providers/gofips
GOFIPS140=v1.0.0 go build -ldflags=-checklinkname=0 -buildmode=c-shared -o "$SCRATCH/libtemperfips.so" .
rc=$?
BUILD_DIR="$PWD"
CHECK $rc "1. README FIPS build command (GOFIPS140=v1.0.0 go build -ldflags=-checklinkname=0 -buildmode=c-shared)"

# 2. approved-mode marker
go version -m "$SCRATCH/libtemperfips.so" | grep -q 'GOFIPS140=v1.0.0-c2097c7c' 
CHECK $? "2. approved-mode marker present (go version -m | grep GOFIPS140)"

# 3. Tag spelling from the docs (page 08, README) vs. the build constraint.
DOCTAG=$(grep -ohE 'tags gofips[-_]debug' docs/audit/08-operating-guide.md README.md 2>/dev/null | head -1 | sed 's/tags //')
CONSTRAINT=$(grep -ohE 'go:build gofips[-_]debug' debug_tag.go | sed 's/go:build //')
echo "  doc tag spelling: '$DOCTAG'; build constraint: '$CONSTRAINT'"
[ -n "$DOCTAG" ] && [ "$DOCTAG" = "$CONSTRAINT" ]
CHECK $? "3a. the documented tag spelling matches the //go:build constraint"
GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build "-tags" "$CONSTRAINT" -buildvcs=false \
  -ldflags=-checklinkname=0 -buildmode=c-shared -o "$SCRATCH/debug.so" .
CHECK $? "3b. debug build with the constraint's tag compiles"
DBGSTR=$(strings "$SCRATCH/debug.so" | grep -c "gcmInit ENTER" || true)
[ "$DBGSTR" -ge 1 ]
CHECK $? "3c. debug build carries the trace strings (feature present; found $DBGSTR)"
# Release silence is not checked with strings(1): the linker keeps the
# dbg() format literals in release builds (the "gofips: " prefix is added
# at runtime). 6a/6b check it at runtime instead.

cd "$SCRATCH/tree"
# 4. C acceptance suite as in the README
cc providers/gofips/testdata/provider_acceptance.c -o "$SCRATCH/pacc" \
  $(pkg-config --cflags --libs libcrypto) -ldl
CHECK $? "4a. README acceptance compile command"
GOFIPS_SO="$SCRATCH/libtemperfips.so" GODEBUG=fips140=on "$SCRATCH/pacc" > "$SCRATCH/pacc.log" 2>&1
CHECK $? "4b. acceptance run under the documented GOFIPS_SO pattern"
grep -q "ALL CHECKS PASSED" "$SCRATCH/pacc.log"
CHECK $? "4c. acceptance result matches the docs' recorded result"

# 5. differential suite per page 12
cc -o "$SCRATCH/diff-suite" providers/gofips/testdata/differential_repro.c \
  $(pkg-config --cflags --libs openssl)
CHECK $? "5a. page-12 differential compile command"
# page 12 loads the provider as <dir>/gofips.so
mkdir -p "$SCRATCH/modematrix-prov"
cp "$SCRATCH/libtemperfips.so" "$SCRATCH/modematrix-prov/gofips.so"
T=0
for t in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  # A case that crashes or prints no verdict counts as a defect.
  out=$(GODEBUG=fips140=on "$SCRATCH/diff-suite" "$SCRATCH/modematrix-prov" "$t" 2>&1); rc=$?
  D=$(echo "$out" | grep -cE 'DEFECT|REGRESSION' || true)
  { [ "$rc" = 0 ] && echo "$out" | grep -qE '^ *ok'; } || D=$((D + 1))
  T=$((T+D))
done
[ "$T" -eq 0 ]
CHECK $? "5b. page-12 differential run: 0 defects across T1-T13"

# 6. trace emission
# The run must pass: a crash before any trace would also print 0 lines.
GOFIPS_DEBUG=1 GODEBUG=fips140=on GOFIPS_SO="$SCRATCH/libtemperfips.so" "$SCRATCH/pacc" 2> "$SCRATCH/rel.err" > "$SCRATCH/rel.out"
REL_RC=$?
REL_LINES=$(grep -c "gofips:" "$SCRATCH/rel.err" || true)
[ "$REL_RC" -eq 0 ] && grep -q "ALL CHECKS PASSED" "$SCRATCH/rel.out" && [ "$REL_LINES" -eq 0 ]
CHECK $? "6a. release build emits NO traces with GOFIPS_DEBUG=1 (got $REL_LINES lines)"
cc providers/gofips/testdata/provider_acceptance.c -o "$SCRATCH/pacc2" \
  $(pkg-config --cflags --libs libcrypto) -ldl
GOFIPS_DEBUG=1 GODEBUG=fips140=on GOFIPS_SO="$SCRATCH/debug.so" "$SCRATCH/pacc2" 2> "$SCRATCH/dbg.err" >/dev/null
DBG_LINES=$(grep -c "gofips:" "$SCRATCH/dbg.err" || true)
[ "$DBG_LINES" -gt 0 ]
CHECK $? "6b. debug build EMITS traces with GOFIPS_DEBUG=1 (got $DBG_LINES lines)"

echo "DOCCLEAN: $FAILS failures"
exit $FAILS
