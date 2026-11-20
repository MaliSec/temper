---
last_updated: 2026-11-19
---

# 10 Evidence manifest

Each release carries the evidence for the provider it ships, as an
attested file attached to the GitHub release:
`gofips-evidence-<release>.tar.gz`. The release workflow produces it from
the release commit:

- `capture/`: every log named below, from the evidence capture
  (`testdata/capture/run.sh`): the suites, the Node integration, the
  OpenSSL 3.0, 3.5 and 4.0 matrix, parity with the OpenSSL FIPS provider,
  and the benchmark.
- `suites-x86_64/` and `suites-aarch64/`: the CI provider suites, run
  natively on each architecture, with the runner's operating environment
  (`gofips-oe.txt`). The algorithm and TLS suites and the benchmark run
  against the shipped `gofips.so` from the release's `temper-gofips`
  package (`gofips-shipped.txt` gives its digest and build marker): C
  acceptance, differential, regtest, GCM lifecycle and caller contract,
  TLS 1.3 and TLS 1.2, SHA-3/PBKDF2, RSA/P-384, EC boundary, panic
  containment, parameter handling. The Node integration, interop, X509 and
  legacy-constructor runners build their own provider, with the debug
  tracing or poisoned variants their checks need.
- `RELEASE.txt`: the release, commit and workflow run. `SHA256SUMS`
  covers every file.

Verify a bundle:

```sh
gh attestation verify gofips-evidence-<release>.tar.gz --repo MaliSec/temper \
  --cert-identity 'https://github.com/MaliSec/temper/.github/workflows/temper-release-build.yml@refs/tags/<release>' \
  --source-ref refs/tags/<release>
tar -xzf gofips-evidence-<release>.tar.gz
(cd gofips-evidence-<release> && sha256sum -c SHA256SUMS)
```

Test sources are under `providers/gofips/testdata/` at the commit
`RELEASE.txt` names. Each log's header gives its environment and command.
In node-integration-full-run.log and tls-surface-amd64.log, debug-trace
values of a throwaway test key and shared secret are redacted. No other
program output is changed.

## Evidence IDs

| ID | Artifact | Path |
|---|---|---|
| E-01 | FIPS C acceptance log | acceptance-fips-build.log, including the SHA-1 non-approved checks |
| E-02 | Default-build acceptance log (fail-closed refusal record; the unstamped build is refused at init) | acceptance-default-build.log |
| E-03 | TLS surface suite amd64 | tls-surface-amd64.log, including the GCM known-answer seal/open/tamper checks |
| E-04 | TLS surface suite arm64 | tls-surface-arm64-qemu.log |
| E-05 | MD5 negative + control | E-01 lines "negative: MD5 NOT fetchable" |
| E-06 | MD5 negative in Node | E-14 stage "Node gates" |
| E-07 | Go digest counter | E-01 "gofips digest operations executed in Go: 3" |
| E-08 | Module integrity evidence | integrity-evidence.txt |
| E-09 | DRBG mode logs | drbg-fips-mode.log + drbg-nonfips-contrast.log |
| E-10 | DRBG path | page 11; Go source `crypto/rand/rand.go`; E-09 and E-01 |
| E-11 | SP boundary text | page 02 of this pack, quoting E-16 |
| E-12 | arm64 build/run evidence | arm64-evidence.txt + acceptance-arm64-qemu.log |
| E-13 | TLS negative gates | node-integration-full-run.log stage "TLS negative gates"; the baseline connects |
| E-14 | Node integration run, real TLS 1.3 handshakes | node-integration-full-run.log; debug-trace values of a throwaway test key and shared secret are redacted |
| E-15 | CMVP certificate #5247 | https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247 |
| E-16 | SP 5247 PDF | https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf |
| E-17 | AES-128-GCM registration | dispatch.c |
| E-18 | AES-256-CBC registration | dispatch.c |
| E-19 | Interop regressions | interop-regression.log (+.js, +run script): gofips client to default server and the reverse both connect |
| E-20 | Session tickets and TLS 1.3 resumption | node-tls-handshake.js gate 5 (Node server and client), interop-regression.js (tickets on, both directions), tests/smoke-fips.sh (Node and Python servers, resumed connections) |
| E-21 | Artifact digests | artifact-digests.txt |
| E-22 | TLS 1.3 over loopback TCP | tls_tcp_handshake.c + tls-tcp-handshake-host.log: gofips on both ends, client and server on separate threads |
| E-23 | ELF no-libcrypto proof | provider README "soname-agnostic" section + E-14 readelf line |
| E-24 | Source review | provider.go, tls.go, tls12.go, gcm_tls13.go, hmac_pkey.go, kdf_sha3.go, rsa.go, dispatch.c, dispatch_abi_compat.h, README.md |
| E-25 | In-image TLS bench | bench-control-amd64.log + bench-gofips-amd64.log |
| E-26 | CI workflows | .github/workflows/temper-build.yml, gofips-suites.yml |
| E-27 | SSL_CTX_new with valid and invalid module paths | ctx-mechanism-run.txt (+ docs/audit/ctxtest.c) |
| E-28 | X509_digest probe, both ABIs | x509_digest_probe.c + run-x509-digest.sh |
| E-29 | CI suites | `.github/workflows/gofips-suites.yml`, run by temper-build on pull requests and pushes to main and by the release against the shipped provider (E-43) |
| E-30 | Differential suite log (T1-T13, 0 defects) | differential-run.log: GCM matches the default provider, record-counter refusals, tag-order limit |
| E-31 | GCM nonce lifecycle log | guardtest-run.log (I1-I6: 70000 records on one key, repeat/decrease/prefix refusals, copies, 6000 keys, 8 threads) + guardunit.c U1-U7 + guardunit-attrib.sh |
| E-32 | Regtest log (dup/free, registry, race) | regtest-run.log |
| E-33 | Build/mode matrix + release-binary runtime-silence scan | mode-matrix-run.log; the scan asserts runtime silence (release build: 0 gofips: trace lines under GOFIPS_DEBUG=1; debug build: traces) |
| E-34 | Acceptance gates | ecboundary.c (EC boundary corpus + cross-provider round trips), panictest.c + panictest-inventory.txt + coverage-inventory.sh + coverage-check.sh (panic containment across every exported family), docclean.sh (documented-command clean checkout) |
| E-35 | Legacy-ctor routing contract gate | legacy_ctor_boundary.c + run-legacy-ctor.sh: configured mode (gofips-only OPENSSL_CONF, default absent) asserts the legacy-ctor ECDH/ECDSA dispatch through gofips via the provider's own counters; control mode (default reachable) asserts gofips claims no dispatch for a default-served derive and the export/re-import interop survives. Official-OpenSSL-FIPS-provider parity measured with the genuine fips.so (3.5.9): identical NULL-propq fetch resolution and identical default-provider serving with the exported scalar; E-36 |
| E-36 | Official-FIPS-provider parity artifact | fips-parity-probe.c + fips-parity-run.log: the genuine OpenSSL FIPS provider (the Rocky Linux 10 build of openssl-fips-provider 3.5.9-1.el10_3) driving the legacy-ctor NULL-propq shape with gofips loaded alongside; fetch resolves to default, gofips counters unchanged, 4.0.3-linked and compat-pair-linked binaries, plus the default control |
| E-37 | TLS 1.3 GCM: adapter unit tests and real handshakes, fips140=on and only | gcm_tls13.go + gcm_tls13_test.go + tls13_handshake.c + tls13-gcm-run.log: the module refuses a repeated record counter with the adapter bypassed; the general GCM path is rejected under fips140=only while the TLS 1.3 path runs; gofips client/server/both against the default provider, both GCM suites, 600 records each plus KeyUpdate |
| E-38 | Provider by OpenSSL version | openssl-versions-check.txt: the E-01, E-30, E-31, E-34 and E-37 suites, regtest, audreg and paramshape13 pass on OpenSSL 3.0.13, 3.5.7, 3.6.5 and 4.0.3, including TLS 1.3 with gofips as the client, the group alias P-256 and concurrent first use |
| E-39 | SHA-3, SHAKE, HMAC-SHA3, HKDF-SHA3, PBKDF2, streaming ECDSA, and parameter handling | sha3_pbkdf2.c + sha3-pbkdf2-run.log, fips140=on and only: results equal the default provider's; PBKDF2 refusals outside SP 800-132; streaming ECDSA sign, verify and mid-stream copies; large KDF inputs, AES-CBC re-init, GCM tag lengths, HKDF modes, HMAC re-keying |
| E-40 | RSA verification, P-384, certificate chains, TLS 1.3 | rsa_p384.c + rsa-p384-run.log, fips140=on and only: RSA-2048/3072/4096 PKCS#1 v1.5 and PSS signatures from the default provider verify, with the refusals of page 03; P-384 keygen, ECDH and ECDSA against the default provider; X509_verify_cert over chains mixing RSA, P-384 and P-256; TLS 1.3 with gofips as client against RSA and P-384 servers and as a P-384 server |
| E-41 | Native arm64 suites | suites-aarch64/ in the bundle: every provider suite on GitHub's `ubuntu-24.04-arm` runner, the Node integration in the arm64 node image, and the TLS benchmark |
| E-42 | TLS 1.2 | tls12.c + tls12-run.log, fips140=on and only: TLS1-PRF equals the default provider's for SHA-256/384/512 and refuses the classic master secret, SHA-1 and MD5-SHA1; TLS 1.2 handshakes (ECDSA and RSA certificates, AES-128/256-GCM) with gofips on one or both ends, 400 records both ways, resumption; CBC suites, ChaCha20, RSA key exchange and peers without the extended master secret refused. tests/smoke-fips.sh: TLS 1.2 to registry.npmjs.org from both images. |
| E-43 | Release suites against the shipped provider | suites-x86_64/ and suites-aarch64/ in the bundle; gofips-shipped.txt names the package and `gofips.so` digests the suites ran against |
| E-44 | OpenSSL 3 and 4 in one process | dual_openssl.c, run by run-dual-openssl.sh in CI (gofips-dual-openssl.log) and in the capture's 3.6.5 matrix: OpenSSL 3.6.5 and 4.0.3 loaded together, each with the config the images ship, share one `gofips.so` built against the OpenSSL 4.0.3 headers; per library, SHA-256/384 and HMAC-SHA256 known answers, MD5 unusable, every digest served by gofips, PEM keys loaded and RAND, then 4 threads per library interleaved |
| E-45 | The config's gofips preference | config_pref.c in the capture matrix (OpenSSL 3.0.13, 3.5.7, 3.6.5, 4.0.3), with the config the images ship: SHA-1 and SHA-256 resolve to gofips, MD5 computes nothing (OpenSSL 3: gofips's refused row; OpenSSL 4: not registered), PEM private and public keys load |
