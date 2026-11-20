#!/usr/bin/env bash
# parity.sh: official-FIPS-provider parity (E-36) and paramshape13 ABIs 1-2.
# Runs in gofips-capture:local (see run.sh). Mounts: /src the repo
# (read-only), /compat the OpenSSL 3.5.9 compat pair, /fips the genuine
# fips.so (fetch-fips-provider.sh), /out results.
set -uo pipefail
trap 'chown -R "${HOST_UID:-0}:${HOST_GID:-0}" /out 2>/dev/null || true' EXIT
# A failing suite is recorded here (subshells included) and makes the
# script exit non-zero at the end; assemble.py checks every result too.
FAILED=/tmp/capture.failed; : > "$FAILED"
failed() { echo "$*" >> "$FAILED"; }
rm -rf /work && cp -r /src /work && P=/work/providers/gofips && T=$P/testdata && O=/out && mkdir -p /tmp/p
cd $P && GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/p/gofips.so . || exit 1
sha256sum /tmp/p/gofips.so | cut -d' ' -f1 > $O/artifact.sha256
sha256sum /fips/fips.so | cut -d' ' -f1 > $O/fips.sha256
INC="$(pkg-config --cflags openssl)"
cc -o /tmp/probe40 $T/fips-parity-probe.c $INC $(pkg-config --libs openssl) || exit 1
cc -o /tmp/probe35 $T/fips-parity-probe.c $INC -L/compat -lcrypto -Wl,-rpath,/compat || exit 1
cc -o /tmp/probectl $T/fips-parity-probe.c -DPARITY_PROVIDER='"default"' $INC $(pkg-config --libs openssl) || exit 1
run() { "$@" 2>&1; local rc=$?; echo "rc=$rc"; [ "$rc" = 0 ] || failed "$*"; }
{
  echo "-- genuine fips provider 3.5.9, gofips loaded alongside, 4.0.3-linked probe --"
  OPENSSL_MODULES=/fips run /tmp/probe40 /tmp/p
  echo
  echo "-- genuine fips provider 3.5.9, gofips loaded alongside, 3.5.9-linked probe (compat pair) --"
  OPENSSL_MODULES=/fips run /tmp/probe35 /tmp/p
  echo
  echo "-- default-provider control (same probe shape, default in place of fips; 4.0.3) --"
  run /tmp/probectl /tmp/p
} > $O/fips-parity-run.body

cc -o /tmp/ps40 $T/paramshape13.c $INC $(pkg-config --libs openssl) || exit 1
cc -o /tmp/ps35 $T/paramshape13.c $INC -L/compat -lcrypto -Wl,-rpath,/compat || exit 1
{
  echo "== ABI 1: host x86-64, OpenSSL 4.0.3 (host libcrypto)"
  (cd /tmp/p && GODEBUG=fips140=on /tmp/ps40 /tmp/p 2>&1) || failed "paramshape13 ABI 1"
  echo
  echo "== ABI 2: x86-64, pinned OpenSSL 3.5.9 compat pair, default provider = 3.5.9"
  sha256sum /compat/libcrypto.so.3
  (cd /tmp/p && GODEBUG=fips140=on /tmp/ps35 /tmp/p 2>&1) || failed "paramshape13 ABI 2"
} > $O/paramshape13-x86.body
if [ -s "$FAILED" ]; then echo "failed suites:" >&2; cat "$FAILED" >&2; exit 1; fi

