#!/usr/bin/env bash
# run-legacy-ctor.sh - legacy-ctor routing gate (E-35). Builds the provider
# and runs legacy_ctor_boundary.c in two fresh processes:
#   configured: gofips-only OPENSSL_CONF; ECDH/ECDSA must dispatch
#               through gofips.
#   control:    no config; the gofips counters must agree with whichever
#               provider the core resolved (see legacy_ctor_boundary.c).
#
# Usage: run-legacy-ctor.sh [libcrypto-dir]
#   libcrypto-dir: an OpenSSL 3.x compat pair to link against
#                  (defaults to pkg-config openssl).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/.."
REPO="$(cd "$PROV/../.." && pwd)"
WORK="$(mktemp -d /tmp/gofips-legacyctor.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
step() { echo; echo "=== $1 ==="; }

LIBDIR="${1:-}"
CCFLAGS="$(pkg-config --cflags openssl)"
LIBS="-ldl"
if [ -n "$LIBDIR" ]; then
  CCFLAGS="$CCFLAGS"
  LIBS="$LIBS -L$LIBDIR -lcrypto -Wl,-rpath,$LIBDIR"
else
  LIBS="$LIBS $(pkg-config --libs openssl)"
fi

step "Build provider (committed tree) + suite"
(
  cd "$PROV"
  GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false \
    -ldflags=-checklinkname=0 -buildmode=c-shared -o "$WORK/gofips.so" . || exit 1
) || { echo "FAIL: provider build"; exit 1; }
cc -o "$WORK/lcb" "$HERE/legacy_ctor_boundary.c" $CCFLAGS $LIBS || {
  echo "FAIL: suite compile"; exit 1; }

step "Configured shape (gofips-only OPENSSL_CONF; default absent)"
sed "s|GOFIPS_MODULE_PATH|$WORK/gofips.so|" \
  "$HERE/node-integration/openssl-gofips.cnf" > "$WORK/openssl.cnf"
OPENSSL_CONF="$WORK/openssl.cnf" GOFIPS_SO="$WORK/gofips.so" \
  "$WORK/lcb" configured || FAILS=$((FAILS+1))

step "Control shape (no config; default reachable; core parity)"
# An inherited OPENSSL_CONF would remove the default provider and void
# the control.
unset OPENSSL_CONF
if [ -n "${OPENSSL_CONF:-}" ]; then
  echo "FAIL: OPENSSL_CONF still set in control shape (env leak)"
  FAILS=$((FAILS+1))
fi
GOFIPS_SO="$WORK/gofips.so" "$WORK/lcb" control || FAILS=$((FAILS+1))

echo
if [ "$FAILS" -eq 0 ]; then
  echo "LEGACY-CTOR BOUNDARY: ALL MODES PASSED"
  exit 0
else
  echo "LEGACY-CTOR BOUNDARY: $FAILS MODE(S) FAILED"
  exit 1
fi
