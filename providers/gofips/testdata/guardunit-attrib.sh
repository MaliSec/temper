#!/usr/bin/env bash
# guardunit-attrib.sh - the attribution gate for GCM nonce reuse. Runs the
# two-attempt seal sequence on the -tags gofips_debug artifact under
# GOFIPS_DEBUG=1 and asserts, from the return codes and the trace:
#   attempt 1 (record 0, fresh key):  sealed.
#   attempt 2 (the same nonce again): refused, and the trace names the
#                                     record-counter check as the reason.
# Any refusal returns 0; only the trace line ties it to nonce reuse.
# gcm_tls13_test.go covers the Go module refusing a repeated counter with
# the adapter check bypassed.
set -uo pipefail
DIR="${1:?usage: guardunit-attrib.sh <dir-containing-gofips.so>}"
BIN="$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cc -o "$WORK/probe" "$BIN/guardunit_seq.c" $(pkg-config --cflags --libs openssl) || { echo "FAIL: probe compile"; exit 1; }

OUT=$(GOFIPS_DEBUG=1 GODEBUG=fips140=on "$WORK/probe" "$DIR" 2>&1)
echo "$OUT" | grep -E "^attempt|REFUSED" | head -10

A1=$(echo "$OUT" | grep -c "^attempt 1 rc=1")
A2=$(echo "$OUT" | grep -c "^attempt 2 rc=0")
TR=$(echo "$OUT" | grep -c "REFUSED: gofips: GCM record counter did not increase")
fails=0
if [ "$A1" -eq 1 ]; then
  echo "PASS: attempt 1 sealed (rc=1)"
else
  echo "FAIL: attempt 1 did not seal"
  fails=$((fails+1))
fi
if [ "$A2" -eq 1 ]; then
  echo "PASS: attempt 2, the same nonce again, was refused (rc=0)"
else
  echo "FAIL: attempt 2 was not refused"
  fails=$((fails+1))
fi
if [ "$TR" -ge 1 ]; then
  echo "PASS: the trace attributes the refusal to the record-counter check (lines=$TR)"
else
  echo "FAIL: no record-counter refusal line in the trace (is this the gofips_debug artifact?)"
  fails=$((fails+1))
fi
[ "$fails" -eq 0 ] && echo "GUARDUNIT-ATTRIB: ALL PASS" || echo "GUARDUNIT-ATTRIB: $fails FAILURES"
exit $fails
