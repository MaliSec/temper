#!/usr/bin/env bash
# matrix.sh: the provider suites against whichever OpenSSL this container
# provides; one summary line per suite (E-38). run.sh runs it on OpenSSL
# 3.0.13 (Ubuntu 24.04), 3.5.7 (Debian), 3.6.5 (Wolfi) and 4.0.3
# (gofips-capture:local). With DUAL_OPENSSL_INCLUDE (OpenSSL 4 headers; the
# container has libcrypto.so.3 and libcrypto.so.4), it also runs
# dual_openssl.c against a gofips.so built as the images ship it (E-44).
# Mount: /src the repo (read-only).
set -uo pipefail
OPENSSL=openssl
OSSL="$(pkg-config --cflags openssl) $(pkg-config --libs openssl)"
# One summary line per suite. A line that is not a pass makes the script
# exit non-zero (assemble.py checks the same lines).
MFAIL=0
res() {
  printf '  %-30s %s\n' "$1" "$2"
  echo "$2" | grep -qE 'ALL PASS|ALL CHECKS PASSED|^0 defects$|^TLS 1\.3 handshake completed|^[1-9][0-9]* pass, 0 fail$|^GOFIPS140=v1\.0\.0-c2097c7c$|^SKIP: ' || MFAIL=1
}
echo "openssl $(pkg-config --modversion openssl), $(go version | awk '{print $3}')"
cp -r /src /work && cd /work/providers/gofips && mkdir -p /tmp/m
CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/m/gofips.so . || { echo "BUILD FAILED"; exit 1; }
res "GOFIPS140 marker" "$(go version -m /tmp/m/gofips.so | awk '$2 ~ /^GOFIPS140=/ {print $2}')"
for mode in on only; do
  out=$(CGO_ENABLED=1 GOFIPS140=v1.0.0 GODEBUG=fips140=$mode go test -buildvcs=false -ldflags=-checklinkname=0 -count=1 \
    -run 'TestModuleRefusesRepeatedCounter|TestSealRefusals|TestOpen|TestMatchesGeneralGCM' -v . 2>&1)
  res "go test fips140=$mode" "$(echo "$out" | grep -c '^--- PASS') pass, $(echo "$out" | grep -c '^--- FAIL') fail"
done
T=/work/providers/gofips/testdata
build() { cc -o "/tmp/$1" "$T/$1.c" $OSSL -lpthread 2>/tmp/cc.err || { echo "compile FAILED: $1"; cat /tmp/cc.err; }; }
for b in tls13_handshake provider_acceptance differential_repro regtest guardtest audreg ecboundary paramshape13 sha3_pbkdf2 rsa_p384 tls12 config_pref; do build $b; done
cd /tmp/m
for mode in on only; do res "tls13_handshake fips140=$mode" "$(GODEBUG=fips140=$mode /tmp/tls13_handshake /tmp/m 2>&1 | grep 'TLS13 HANDSHAKE' | tail -1)"; done
res "C acceptance" "$(GOFIPS_SO=/tmp/m/gofips.so GODEBUG=fips140=on /tmp/provider_acceptance 2>&1 | grep -E 'ALL CHECKS|FAIL' | tail -1)"
# Each case must run (exit 0, at least one "ok" verdict); a crash is not
# "0 defects".
D=0; for t in $(seq 1 13); do
  out=$(GODEBUG=fips140=on /tmp/differential_repro /tmp/m "$t" 2>&1); rc=$?
  n=$(echo "$out" | grep -cE 'DEFECT|REGRESSION' || true)
  { [ "$rc" = 0 ] && echo "$out" | grep -qE '^ *ok'; } || n=$((n + 1))
  D=$((D+n))
done
res "differential T1-T13" "$D defects"
mkdir -p /tmp/modematrix && cp /tmp/m/gofips.so /tmp/modematrix/gofips.so
res "regtest" "$(GODEBUG=fips140=on /tmp/regtest 2>&1 | tail -1)"
res "guardtest" "$(GODEBUG=fips140=on /tmp/guardtest /tmp/m 2>&1 | tail -1)"
a=$(GODEBUG=fips140=on timeout 120 /tmp/audreg /tmp/m 2>&1)
res "audreg" "$(echo "$a" | grep '^AUDREG: [0-9A]' | tail -1)$(echo "$a" | grep -c '^SKIP' | sed 's/^0$//; s/^\([1-9]\)$/ (\1 skipped)/')"
echo "$a" | grep -E '^FAIL|names:|first-use:' | sed 's/^/      /'
res "ecboundary" "$(GODEBUG=fips140=on /tmp/ecboundary /tmp/m 2>&1 | grep -E 'ALL PASS|FAIL' | tail -1)"
res "paramshape13" "$(GODEBUG=fips140=on /tmp/paramshape13 /tmp/m 2>&1 | grep -E 'PARAMSHAPE13:' | tail -1)"
res "sha3_pbkdf2" "$(GODEBUG=fips140=on /tmp/sha3_pbkdf2 /tmp/m 2>&1 | grep -E 'SHA3PBKDF2:' | tail -1) ($(GODEBUG=fips140=on /tmp/sha3_pbkdf2 /tmp/m 2>&1 | grep -c '^PASS') checks)"
for mode in on only; do res "rsa_p384 fips140=$mode" "$(GODEBUG=fips140=$mode /tmp/rsa_p384 /tmp/m 2>&1 | grep -E '^RSAP384:' | tail -1)"; done
for mode in on only; do res "tls12 fips140=$mode" "$(GODEBUG=fips140=$mode /tmp/tls12 /tmp/m 2>&1 | grep -E '^TLS12:' | tail -1)"; done
# Real client/server handshake with -groups P-256 (alias) and gofips as client.
cd /tmp
$OPENSSL req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -subj /CN=t -keyout key.pem -out cert.pem -days 1 2>/dev/null
sed "s|GOFIPS_MODULE_PATH|/tmp/m/gofips.so|" $T/node-integration/openssl-gofips.cnf > g.cnf
sleep 8 | timeout 10 $OPENSSL s_server -accept 4499 -tls1_3 -cert cert.pem -key key.pem -naccept 1 >/tmp/srv.log 2>&1 &
sleep 2
r=$(sleep 2 | GODEBUG=fips140=on OPENSSL_CONF=/tmp/g.cnf timeout 10 $OPENSSL s_client -connect 127.0.0.1:4499 -tls1_3 -groups P-256 2>&1)
if echo "$r" | grep -qE 'Cipher is TLS_AES_(128|256)_GCM_SHA(256|384)' && ! echo "$r" | grep -q 'alert'; then
  res "s_client -groups P-256" "TLS 1.3 handshake completed ($(echo "$r" | grep -oE 'Cipher is TLS_[A-Z0-9_]+' | head -1))"
else
  res "s_client -groups P-256" "FAILED: $(echo "$r" | grep -m1 -E 'error|alert|failed' | cut -c1-80)"
fi
wait
# The config the images ship, against this OpenSSL (E-45).
sed "s|/usr/lib/ossl-modules/gofips.so|/tmp/m/gofips.so|" /work/providers/gofips/openssl-gofips.cnf > /tmp/pref.cnf
c=$(OPENSSL_CONF=/tmp/pref.cnf GODEBUG=fips140=on /tmp/config_pref 2>&1)
res "config preference" "$(echo "$c" | grep -E '^CONFIGPREF:' | tail -1)"
echo "$c" | grep '^FAIL' | sed 's/^/      /'
# OpenSSL 3 and 4 in one process, sharing one gofips.so built against the
# OpenSSL 4 headers and the config the images ship, as in the node images
# (E-44).
if [ -n "${DUAL_OPENSSL_INCLUDE:-}" ]; then
  mkdir -p /tmp/m4
  (cd /work/providers/gofips && CGO_ENABLED=1 GOFIPS140=v1.0.0 CGO_CFLAGS="-I$DUAL_OPENSSL_INCLUDE" \
    go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/m4/gofips.so .) \
    && cc -o /tmp/dual_openssl "$T/dual_openssl.c" -ldl -lpthread \
    && sed "s|/usr/lib/ossl-modules/gofips.so|/tmp/m4/gofips.so|" /work/providers/gofips/openssl-gofips.cnf > /tmp/g4.cnf \
    && d=$(GODEBUG=fips140=on /tmp/dual_openssl /tmp/g4.cnf 2>&1) || true
  res "dual OpenSSL 3+4" "$(echo "${d:-}" | grep -E '^DUALOPENSSL:' | tail -1 || true)"
  echo "${d:-}" | grep '^FAIL' | sed 's/^/      /'
else
  res "dual OpenSSL 3+4" "SKIP: needs libcrypto.so.3 and libcrypto.so.4"
fi
exit $MFAIL
