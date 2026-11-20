#!/usr/bin/env bash
# host.sh: host suites, Node integration, interop and benchmark captures.
# Runs in gofips-capture:local (see run.sh). Mounts: /src the repo
# (read-only), /compat the OpenSSL 3.5.9 compat pair, /out log bodies, and
# $SHARED at the same path as on the host.
set -uo pipefail
# The repo copy and temp files live under $SHARED, mounted at the same path
# on the host, so scripts that bind-mount their own directories into
# containers (run-tls-bench.sh) work through the host's docker socket.
SHARED=${SHARED:?}
trap 'chown -R "${HOST_UID:-0}:${HOST_GID:-0}" /out "$SHARED" 2>/dev/null || true' EXIT
rm -rf "$SHARED/temper" "$SHARED/tmp"; mkdir -p "$SHARED/tmp"; cp -r /src "$SHARED/temper"
export TMPDIR="$SHARED/tmp"
R=$SHARED/temper; P=$R/providers/gofips; T=$P/testdata; O=/out
OSSL="$(pkg-config --cflags openssl) $(pkg-config --libs openssl)"
strip_times() { sed -E 's/ \([0-9.]+s\)$//; s/^(ok\s+\S+)\s+[0-9.]+s$/\1/; s/^(---\s+(PASS|FAIL|SKIP):\s+\S+)\s*$/\1 /'; }
say() { echo ">>> $*" >&2; }
# A failing suite is recorded here (subshells included) and makes the
# script exit non-zero at the end; assemble.py checks every result too.
FAILED=/tmp/capture.failed; : > "$FAILED"
failed() { echo "$*" >> "$FAILED"; }

say "release build"
mkdir -p /tmp/modematrix
cd $P && GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/modematrix/gofips.so . || exit 1
sha256sum /tmp/modematrix/gofips.so | cut -d' ' -f1 > $O/artifact.sha256
date -u +%Y-%m-%dT%H:%M:%SZ > $O/date.txt

for b in differential_repro guardtest regtest tls13_handshake provider_acceptance tls_tcp_handshake sha3_pbkdf2 rsa_p384 tls12; do
  cc -o /tmp/$b $T/$b.c $OSSL -lpthread -ldl || { echo "compile failed: $b"; exit 1; }
done

say "differential (E-30)"
( cd /tmp/modematrix && for t in $(seq 1 13); do echo "=== T$t ==="; GODEBUG=fips140=on /tmp/differential_repro /tmp/modematrix "$t" 2>&1 || failed "differential T$t"; done ) > $O/differential-run.body

say "guardtest (E-31), regtest"
( cd /tmp/modematrix && GODEBUG=fips140=on /tmp/guardtest /tmp/modematrix ) > $O/guardtest-run.body 2>&1 || failed guardtest
GODEBUG=fips140=on /tmp/regtest > $O/regtest-run.body 2>&1 || failed regtest   # loads gofips from /tmp/modematrix

say "TLS 1.3 GCM (E-37)"
{
  cd $P
  for mode in on only; do
    echo; echo "== go test -run 'TestModuleRefusesRepeatedCounter|TestSealRefusals|TestOpen|TestMatchesGeneralGCM' -v ., GODEBUG=fips140=$mode"
    GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 GODEBUG=fips140=$mode go test -buildvcs=false -ldflags=-checklinkname=0 -count=1 \
      -run 'TestModuleRefusesRepeatedCounter|TestSealRefusals|TestOpen|TestMatchesGeneralGCM' -v . 2>&1 | grep -vE '^=== RUN' | strip_times \
      || failed "go test fips140=$mode"
  done
  for mode in on only; do
    echo; echo "== tls13_handshake, GODEBUG=fips140=$mode"
    GODEBUG=fips140=$mode /tmp/tls13_handshake /tmp/modematrix 2>&1 || failed "tls13_handshake fips140=$mode"
  done
} > $O/tls13-gcm-run.body

say "SHA-3, PBKDF2, streaming ECDSA (E-39)"
for mode in on only; do
  echo "== GODEBUG=fips140=$mode"
  GODEBUG=fips140=$mode /tmp/sha3_pbkdf2 /tmp/modematrix 2>&1 || failed "sha3_pbkdf2 fips140=$mode"
done > $O/sha3-pbkdf2-run.body

say "RSA verification, P-384, chains and TLS (E-40)"
for mode in on only; do
  echo "== GODEBUG=fips140=$mode"
  GODEBUG=fips140=$mode /tmp/rsa_p384 /tmp/modematrix 2>&1 || failed "rsa_p384 fips140=$mode"
done > $O/rsa-p384-run.body

say "TLS 1.2 (E-42)"
for mode in on only; do
  echo "== GODEBUG=fips140=$mode"
  GODEBUG=fips140=$mode /tmp/tls12 /tmp/modematrix 2>&1 || failed "tls12 fips140=$mode"
done > $O/tls12-run.body

say "mode matrix (E-33)"
bash $T/mode-matrix.sh > $O/mode-matrix-run.body 2>&1 || failed mode-matrix

say "default build refusal (E-02)"
cd $P && CGO_ENABLED=1 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/temperfips-default.so . || exit 1
GOFIPS_SO=/tmp/temperfips-default.so /tmp/provider_acceptance > $O/acceptance-default-build.body 2>&1

say "guardcheck classification"
{
  echo "== selftest (synthetic classifier fixtures)"
  bash $T/guardcheck.sh --selftest 2>&1 | sed -E "s#($TMPDIR|/tmp)/tmp\.[A-Za-z0-9]+#<tmp>#g"; echo "exit=${PIPESTATUS[0]}"
  echo; echo "== real tree classification"
  bash $T/guardcheck.sh $R 2>&1; echo "exit=${PIPESTATUS[0]}"
} > $O/guardcheck-classification.body
bash $T/coverage-inventory.sh > $O/panictest-inventory.check 2>&1

say "integrity (E-08), DRBG modes (E-09)"
cd $P && GOFIPS140=v1.0.0 go build -o /tmp/fipsmode ./testdata/fipsmode || exit 1
sha256sum "$(go env GOROOT)/lib/fips140/v1.0.0-c2097c7c.zip" | cut -d' ' -f1 > $O/zip.sha256
go version -m /tmp/modematrix/gofips.so | grep -E 'build\s+(-tags|DefaultGODEBUG|GOFIPS140)' > $O/so-markers.txt
GODEBUG=fips140=on /tmp/fipsmode > $O/drbg-fips-mode.body 2>&1
GODEBUG=fips140=off /tmp/fipsmode > $O/drbg-nonfips-contrast.body 2>&1

say "TCP handshake (E-22)"
GODEBUG=fips140=on /tmp/tls_tcp_handshake /tmp/modematrix > $O/tls-tcp-handshake-host.body 2>&1 || failed tls_tcp_handshake

say "SSL_CTX_new mechanism (E-27)"
mkdir -p /tmp/ctx && cp /tmp/modematrix/gofips.so /tmp/ctx/temperfips.so
cc $P/docs/audit/ctxtest.c -o /tmp/ctxtest $(pkg-config --cflags --libs libssl libcrypto) || exit 1
sed "s|GOFIPS_MODULE_PATH|/tmp/ctx/temperfips.so|" $T/node-integration/openssl-gofips.cnf > /tmp/ctx/good.cnf
sed "s|GOFIPS_MODULE_PATH|/gofips/temperfips.so|" $T/node-integration/openssl-gofips.cnf > /tmp/ctx/bad.cnf
{ echo "== valid module path"; OPENSSL_CONF=/tmp/ctx/good.cnf GODEBUG=fips140=on /tmp/ctxtest 2>&1; echo "rc=$?"
  echo; echo "== invalid module path (/gofips/temperfips.so, container-only)"
  OPENSSL_CONF=/tmp/ctx/bad.cnf GODEBUG=fips140=on /tmp/ctxtest 2>&1; echo "rc=$?"; } > $O/ctxtest.body

say "node integration (E-13, E-14, E-03, E-01)"
GOFIPS_LIBCRYPTO_DIR=/compat bash $T/node-integration/run-node-integration.sh node:local-amd64 > $O/node-integration-full-run.body 2>&1
rc=$?; echo "rc=$rc" >> $O/node-integration-full-run.body; [ "$rc" = 0 ] || failed node-integration

say "interop regressions (E-19)"
bash $T/node-integration/run-interop-regression.sh node:local-amd64 > $O/interop-regression.body 2>&1
rc=$?; echo "rc=$rc" >> $O/interop-regression.body; [ "$rc" = 0 ] || failed interop

say "TLS benchmark (E-25)"
# One stream through a pipe: the script tees each run to /dev/stderr, and a
# file redirect would be truncated by each tee.
bash $T/node-integration/run-tls-bench.sh node:local-amd64 2>&1 | cat > $O/bench.all
rc=${PIPESTATUS[0]}; echo "rc=$rc" >> $O/bench.all; [ "$rc" = 0 ] || failed bench
say "done"
if [ -s "$FAILED" ]; then echo "failed suites:" >&2; cat "$FAILED" >&2; exit 1; fi

