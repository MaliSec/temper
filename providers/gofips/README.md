# gofips: an OpenSSL provider backed by the Go Cryptographic Module

An OpenSSL 3.x/4.x provider whose cryptographic operations run in the Go
Cryptographic Module (CMVP #5247, module v1.0.0). Loaded as the only
provider with algorithms, it leaves OpenSSL's EVP and TLS plumbing in place
(Node's and Python's included) and serves EVP operations from the
validated module (SHA-1 and AES-CBC chaining excepted, audit page 03).
libcrypto's built-in low-level APIs bypass EVP and are not covered (audit
page 09). The `node-fips` and `python-fips` images ship it
(`packages/gofips`).

## FIPS status

| What is validated | What the reliance rests on |
|---|---|
| Go Cryptographic Module v1.0.0 = CMVP #5247 (FIPS 140-3, Active, L1, sunset 2031-04-26; CAVP A6650, A8668) | The adapter calls the validated module through Go's crypto APIs, unmodified (TLS record protection and the TLS 1.2 KDF through `crypto/tls` functions, audit page 03) |
| The build mode per SP §11.1: `GOFIPS140=v1.0.0` with the unmodified frozen archive `v1.0.0-c2097c7c.zip` (sha256 `daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b`) | The SP boundary (section 2.1) is the entire module executable code, the module serves calling applications at the API level (sections 2.10, 2.11), and SSPs are exchanged electronically with external callers (section 9.2): a calling application in any language, including a c-shared library, is the designed use |
| Artifact, build, OE and self-test evidence: approved-mode build marker, HMAC-SHA2-256 integrity check and KATs passing at init (audit pack pages 02, 04, 13) | The audit pack traces each SP condition to evidence |

Per the SP, the module boundary is "the entire Go Cryptographic Module
executable code", and the module offers its services at the API level to
calling applications. The adapter relies on the module when the SP's
artifact, build, OE and self-test conditions hold in the deployment; the
audit pack (providers/gofips/docs/audit/) traces each condition to the
evidence each release attaches (audit page 10).

## Files

- `provider.go`, cgo exports: `OSSL_provider_init`, provider-level
  params/teardown/query/random-bytes, the digest operation (newctx/init/
  update/final/freectx + param handling), and the RAND operation
  (a CTR-DRBG-shaped pass-through to `crypto/rand`, which in FIPS mode is
  the module's SP 800-90A DRBG; see "RAND / DRBG status" below). SHA-256 via
  `crypto/sha256` (routes through `crypto/internal/fips140/sha256` when
  `GOFIPS140=v1.0.0`); RAND via `crypto/rand`.
- `tls.go`, the TLS surface: SHA-384/512, HMAC, HKDF, TLS13-KDF, AES,
  EC key management (P-256, P-384), ECDH and ECDSA. `gcm_tls13.go`, AES-GCM
  through the module's TLS 1.3 GCM service. `tls12.go`, the TLS 1.2 KDF
  (TLS1-PRF) and TLS 1.2 GCM records. `hmac_pkey.go`, HMAC as a key and a
  signature (the TLS 1.3 PSK binder).
- `kdf_sha3.go`, SHA-3, SHAKE and PBKDF2. `rsa.go`, RSA public keys and
  RSA signature verification.
- `debug_tag.go`, `debug_release.go`, the debug-trace switch: on only in a
  `-tags gofips_debug` build.
- `openssl-gofips.cnf`, the gofips-only OpenSSL config the `-fips` images
  ship.
- `dispatch.c`, C-side `OSSL_DISPATCH` / `OSSL_ALGORITHM` /
  `OSSL_PARAM` / `OSSL_ITEM` tables (function pointers must live in C;
  cgo cannot take Go function addresses from Go code). Also hosts the
  provider-name/version/status param table and the reason-strings table.
- `testdata/provider_acceptance.c`, the acceptance test (vectors,
  negatives, default-provider positive control, Go-side evidence counter).
- `testdata/capture/`, the evidence capture the release workflow runs
  for each release's evidence bundle.

## Build, soname-agnostic (no libcrypto dependency)

A provider receives core callbacks through `OSSL_provider_init` and needs
no libcrypto symbols of its own. The build links no libcrypto: the object
has no libcrypto-namespaced undefined symbols (checked with
`nm -D --undefined-only`) and carries only `DT_NEEDED libc.so.6`, so the
same .so loads on OpenSSL 3.x and 4.x. One artifact passes the C
acceptance suite on OpenSSL 3.0, 3.5 and 4.0 and runs inside the node
image (OpenSSL 4.0.3).

## arm64

CI builds and runs every suite natively on arm64 (GitHub's
`ubuntu-24.04-arm` runners) as well as on amd64, including the Node
integration suite in the arm64 node image and the TLS benchmark (audit
E-41). The build and test commands work unchanged on an arm64 Linux host.

The capture also cross-builds the provider for arm64 and runs it under
`qemu-aarch64` (`arm64-evidence.txt`, `acceptance-arm64-qemu.log` in the
evidence bundle). Emulation shows functional correctness only.

## What is served

1. Digests: SHA-256/384/512, SHA3-224/256/384/512, SHAKE-128/256.
2. MACs and KDFs: HMAC with SHA-2 or SHA-3 (112-bit key floor), also as
   an HMAC key and signature for the TLS 1.3 PSK binder; HKDF, TLS13-KDF,
   PBKDF2 within SP 800-132's approved conditions.
3. AES-128/256-GCM through the module's TLS 1.3 GCM service, which
   enforces the record counter itself (see "AES-GCM"), and AES-128/256-CBC
   for session tickets (without `fips=yes`).
4. EC P-256 and P-384: key generation, ECDH, ECDSA.
5. RSA signature verification (PKCS#1 v1.5 and PSS) with keys the module
   approves. No RSA private keys.
6. TLS 1.3, and TLS 1.2 with AES-GCM and the extended master secret,
   through libssl as client and server, with session tickets and
   resumption, including public endpoints with RSA certificate chains.
   TLS 1.2 uses the module's TLS 1.2 KDF and TLS 1.2 GCM (see "TLS 1.2").

Each has known-vector or differential evidence against the default
provider in the release's evidence bundle, and the provider's
per-operation counters record the operations it served. Fail-closed
surface: MD5, X25519, ChaCha20-Poly1305, P-521, RSA private-key
operations, TLS 1.1 and older, and TLS 1.2 CBC suites are not served; the
full list is audit page 03. SHA-1 is registered as an explicitly
non-approved digest (`fips=no`): it runs outside the validated module, for
non-security identifiers only, and is not accepted by HMAC, HKDF, PBKDF2
or a signature.

## Tables in C

The reason-string and provider param tables live in `dispatch.c`:
OpenSSL 3.5 iterates the reason-string table without a NULL check, and Go
strings are not NUL-terminated.

## AES-GCM

OpenSSL's TLS stack computes each record nonce and hands it to the
provider. The Go module's public GCM (`cipher.NewGCM`) treats that as an
arbitrary nonce, which is non-approved for encryption. The module also
has a TLS 1.3 GCM service that learns the static IV from the first
record and refuses any nonce whose counter does not increase; Go's own
`crypto/tls` uses it. The provider reaches that service through
`crypto/tls.aeadAESGCMTLS13`, a function Go keeps linkable for existing
outside users (`gcm_tls13.go`). TLS 1.3 through libssl, Node's included,
works on it, and it passes under `GODEBUG=fips140=only`.

Constraints:
- The Security Policy lists that service (`NewGCMForTLS13`) as an
  approved way to generate GCM IVs, for use in the context of TLS 1.3
  (SP 2.7; audit page 03). The GCM algorithms carry `fips=yes` on that
  basis. The claim covers TLS record protection, not
  application-level GCM. The `crypto/tls` function used to reach it
  is not public Go API, which is an upgrade risk.
- It is the TLS record pattern. A multi-update encrypt is refused, and a
  decrypt needs the tag before the data.

## TLS 1.2

TLS 1.2 runs on two more module services, reached through `crypto/tls`
the same way (`tls12.go`):

- The TLS 1.2 KDF (SP 800-135, `tls12.PRF`), registered as OpenSSL's
  `TLS1-PRF` with SHA-256, SHA-384 or SHA-512. It refuses the classic
  master secret, so a TLS 1.2 peer must support the extended master
  secret (RFC 7627), as FIPS 140-3 IG D.Q requires.
- TLS 1.2 GCM (`NewGCMForTLS12`, an SP 2.7 approved IV mechanism), driven
  by libssl's TLS 1.2 record mode: the provider numbers each sealed
  record's explicit nonce from zero and the module refuses one that does
  not increase.

Only ECDHE suites with AES-GCM are served. CBC suites fail closed: the
provider refuses libssl's TLS CBC record mode.

The two `crypto/tls` functions (`prf12`, `aeadAESGCM`) carry no linkname
marker, so the provider is linked with `-ldflags=-checklinkname=0`; a
build without it fails to link. `testdata/tls12.c` (E-42) checks both
against the default provider in CI.

## RAND / DRBG status, SP 800-90A path

The provider's RAND operation forwards to Go `crypto/rand.Read`, which, in
a FIPS 140-3 runtime (GOFIPS140=v1.0.0 build + GODEBUG=fips140=on), routes
through the Go Cryptographic Module's SP 800-90A Rev. 1 CTR DRBG
(`crypto/internal/fips140/drbg.Read`). Source-level proof in the toolchain
(`crypto/rand/rand.go`): `if fips140.Enabled { drbg.Read(b) }`. The DRBG's
CTR_DRBG Known-Answer Test (per FIPS 140-3 IG 10.3.A R7: instantiate with
known entropy, reseed, generate, compare) runs at module init and aborts
the process on failure; observed passing. Evidence and the OpenSSL-to-Go
mapping: audit page 11, `drbg-fips-mode.log` and
`acceptance-fips-build.log` in the evidence bundle (EVP_RAND
instantiate/generate/reseed green, Go-side call counter via provider-level
params, strength=256/state=instantiated, two generates differ, negative
gate `GOFIPS_REQUIRE_FIPS=1` rejects a non-FIPS artifact).

In a FIPS-mode Go runtime (`GODEBUG=fips140=on`, set in the images), RAND
output is produced by the #5247 module's SP 800-90A DRBG. The module
handles entropy internally.

## Node integration (Temper node image)

`testdata/node-integration/` runs the provider inside the node image with
`openssl-gofips.cnf`, which activates gofips as the only provider. It
checks:

- Node starts: its CSPRNG bootstrap fetches `CTR-DRBG`, which gofips
  serves from Go crypto/rand (see "RAND / DRBG status").
- Every fetch resolves from gofips or fails closed: MD5 throws, since the
  default provider that would serve it is absent. SHA-1 is served as a
  labelled non-approved digest.
- Node really runs gofips: a poisoned build (SHA-256 first output byte
  flipped, 0xba to 0x45) changes what `createHash('sha256')` returns.
- Real TLS 1.3 handshakes complete.

The provider links no libcrypto (only `DT_NEEDED libc.so.6`), so one build
loads under OpenSSL 3.x and 4.x; see "Build, soname-agnostic". If it fails
to load, Node aborts with `Assertion failed: ncrypto::CSPRNG(nullptr, 0)`.

Run it:

```sh
providers/gofips/testdata/fetch-compat-openssl3.sh /tmp/compat-openssl3
export GOFIPS_LIBCRYPTO_DIR=/tmp/compat-openssl3   # the OpenSSL 3 ABI the C stages link
docker load -i dist/node.tar   # -> node:local-amd64 or node:local-arm64
providers/gofips/testdata/node-integration/run-node-integration.sh
```

Each release's evidence bundle has the run as
`node-integration-full-run.log`. The full audit pack is in
providers/gofips/docs/audit/.
