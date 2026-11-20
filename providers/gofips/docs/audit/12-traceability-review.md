---
last_updated: 2026-11-19
---

# 12 Traceability and reproduction

## Source-to-claim traceability

| Claim (page) | Source | Evidence |
|---|---|---|
| Module v1.0.0 is CMVP #5247, Active, L1 (02) | NIST certificate | E-15 |
| Approved algorithms; services (03) | SP 5247 Tables 6, 7, 12 | E-16 |
| Integrity self-test and KATs at init (02) | SP 5247 sections 5.1, 10.1 | E-16 + E-08 |
| Build per SP 11.1, digest and marker (02, 04) | SP 5247 section 11.1 | E-16 + E-08 |
| Tested/affirmed OEs (02) | SP 5247 Tables 3, 4 | E-16 |
| Crypto executes in Go, per op class (01, 03, 06) | counters + traces in logs | E-01, E-03, E-07, E-14 |
| Exclusive routing, fail closed (01, 05) | negative gates + poison control | E-05, E-06, E-13, E-14 |
| GCM served through the module's TLS 1.3 GCM; passes under fips140=only (03) | Go unit tests + handshake test | E-37 |
| GCM record counter: repeat/decrease refused, copies share it, no caps, concurrency (03) | guardtest I1-I6, guardunit U1-U7 | E-31 |
| SHA-1 served as non-approved; fips=yes and HMAC use refused (03) | acceptance + Node gates | E-01, E-14 |
| Differential T1-T13, 0 defects (06) | differential-run.log | E-30 |
| Build/mode matrix, release-binary runtime-silence scan (05) | mode-matrix-run.log | E-33 |
| Same .so on OpenSSL 3.x and 4.x (01, 04) | readelf + verified loads | E-23, E-01, E-14 |
| X509_digest via gofips, both ABIs (03, 06) | probe + CI | E-28, E-29 |
| CI runs the full suite set on pull requests and pushes to main | workflow job | E-29 |
| SSL_CTX_new with valid and invalid module paths (05) | path repro | E-27 |
| EC scalar boundary + cross-provider round trips (03) | ecboundary C1-C11, X1-X2, P0-P5 | E-34 |
| Panic containment, all exported families (05) | panictest + inventory | E-34 |
| Documented commands work on a clean checkout | docclean | E-34 |
| Release evidence is from the shipped provider, both architectures | evidence bundle, gofips-shipped.txt | E-43 |
| arm64 native suites; qemu record functional only (10) | suites-aarch64/, arm64-evidence.txt | E-41, E-12 |
| RAND reaches module DRBG, fips140=on (11) | source + logs | E-10, E-09 |
| Perf deltas and parity (07) | BENCH-JSON lines | E-25 |

## Reproduction commands

All logs and captured records regenerate in one run with
`testdata/capture/run.sh` (testdata/capture/README.md). The individual
commands:

```sh
# C acceptance suite (amd64)
cc providers/gofips/testdata/provider_acceptance.c -o pacc \
  $(pkg-config --cflags --libs libcrypto) -ldl
GOFIPS_SO=$PWD/gofips.so GODEBUG=fips140=on ./pacc

# TLS surface suite
cc providers/gofips/testdata/tls_surface_test.c -o tsurf \
  $(pkg-config --cflags --libs libcrypto) -ldl
GOFIPS_SO=$PWD/gofips.so GODEBUG=fips140=on ./tsurf

# Module mode and DRBG (E-08, E-09)
(cd providers/gofips && GOFIPS140=v1.0.0 go build -o fipsmode ./testdata/fipsmode)
GODEBUG=fips140=on providers/gofips/fipsmode
GODEBUG=fips140=off providers/gofips/fipsmode

# TLS 1.3 over loopback TCP, gofips on both ends (E-22)
cc providers/gofips/testdata/tls_tcp_handshake.c -o tcphs \
  $(pkg-config --cflags --libs openssl) -lpthread
GODEBUG=fips140=on ./tcphs <dir-with-gofips.so>

# Official FIPS provider parity (E-36); add -DPARITY_PROVIDER='"default"'
# for the default-provider control
cc providers/gofips/testdata/fips-parity-probe.c -o parity \
  $(pkg-config --cflags --libs openssl)
OPENSSL_MODULES=<dir-with-genuine-fips.so> ./parity <dir-with-gofips.so>

# OpenSSL 3.5 compat pair (sha-verified per page 04), used by the Node
# integration's C stages and the X509 digest probe
providers/gofips/testdata/fetch-compat-openssl3.sh /tmp/compat-openssl3
export GOFIPS_LIBCRYPTO_DIR=/tmp/compat-openssl3

# Node integration + interop (real TLS handshakes)
docker load -i dist/node.tar
providers/gofips/testdata/node-integration/run-node-integration.sh
providers/gofips/testdata/node-integration/run-interop-regression.sh
providers/gofips/testdata/node-integration/run-tls-bench.sh   # E-25 (amd64 capture), E-41 (arm64, CI); native only

# X509 digest probe
providers/gofips/testdata/node-integration/run-x509-digest.sh \
  node:local-amd64 /tmp/compat-openssl3/libcrypto.so.3

# Differential suite T1-T13 (0 defects)
cc -o diff-suite providers/gofips/testdata/differential_repro.c \
  $(pkg-config --cflags --libs openssl)
for t in 1 2 3 4 5 6 7 8 9 10 11 12 13; do ./diff-suite <dir-with-gofips.so> $t; done

# SSL_CTX_new mechanism reproduction (E-27)
cc providers/gofips/docs/audit/ctxtest.c -o ctxtest \
  $(pkg-config --cflags --libs libssl libcrypto)
sed 's|GOFIPS_MODULE_PATH|<dir-with-gofips.so>/gofips.so|' \
  providers/gofips/testdata/node-integration/openssl-gofips.cnf > gofips-host.cnf
OPENSSL_CONF=gofips-host.cnf ./ctxtest

# Acceptance gates (E-34)
cc providers/gofips/testdata/ecboundary.c -o ecb $(pkg-config --cflags --libs openssl)
GODEBUG=fips140=on ./ecb <dir-with-gofips.so>
bash providers/gofips/testdata/docclean.sh

# Verify the frozen module archive
sha256sum "$(go env GOROOT)/lib/fips140/v1.0.0-c2097c7c.zip"
```
