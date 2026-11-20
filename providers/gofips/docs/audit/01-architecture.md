---
last_updated: 2026-11-19
---

# 01 Executive architecture

## What was built

`gofips.so` is an OpenSSL 3.x/4.x provider whose cryptographic
operations are performed by the Go Cryptographic Module v1.0.0 (CMVP #5247).
It is loaded into consumers such as Node.js through the standard OpenSSL
provider interface.

## Division of responsibility

```
+--------------------------------------------------------------+
| Application (Node.js / any OpenSSL consumer)                   |
|   protocol handling, X.509 parsing, TLS state machine          |
|   stays in OpenSSL core + base provider                        |
+--------------------------------------------------------------+
| OpenSSL EVP layer (libcrypto)                                  |
+--------------------------------------------------------------+
| gofips provider adapter (gofips.so)                            |
|   init, dispatch tables, param handling, framing/validation    |
|   (see below); approved transformations are the module's      |
+--------------------------------------------------------------+
| Go Cryptographic Module v1.0.0 (CMVP #5247)                    |
|   SHA-2/3, HMAC, HKDF, PBKDF2, TLS 1.2 KDF, AES-GCM,           |
|   AES block, EC P-256/P-384, RSA verify, CTR DRBG              |
+--------------------------------------------------------------+
```

Evidence: E-24 (source, providers/gofips/tls.go header comment), E-01 to
E-04 (test logs proving each algorithm executes in Go via call counters).

## Two OpenSSL ABIs, one provider

The provider object carries no libcrypto dependency (no `DT_NEEDED
libcrypto.so.N`), so the same `.so` loads under OpenSSL 3.x and 4.x, and
one process can load it from both generations (for example Node's
OpenSSL 4.0.3 and an isolated OpenSSL 3.5 library). `OSSL_provider_init`
can then fire more than once per process. Evidence: E-23 (zero libcrypto
undefined symbols).

## No native provider fallback

Deployment configs activate gofips as the sole crypto provider: default and
legacy providers are absent from every config used in this pack. Any
algorithm gofips does not register fails closed at fetch. Evidence: E-05,
E-06 (MD5), E-13 (ChaCha and the full negative gate list).

## What "the adapter performs no cryptography of its own" means

The adapter performs no approved cryptographic transformation of its own:
every encrypt, decrypt, digest, MAC, KDF, sign, verify, keygen, derive and
random generation executes inside the Go Cryptographic Module. The adapter
does execute data handling around those calls: PKCS#7 padding
framing for AES-CBC (the module's SP 800-38A service covers the block
chaining), RFC 8446 section 7.1 label construction for TLS13-KDF
(spec-defined framing over the module's HKDF service), EC scalar
validation (ScalarBaseMult over the module's P-256/P-384 arithmetic, fail-closed
at import/export), and record-buffer placement for the one-shot AEAD
model. These are adapter plumbing over the module's primitives, not
module services.

## Bounded claims

1. In a `GOFIPS140=v1.0.0` build with `GODEBUG=fips140=on`, the
   cryptographic operations the provider serves execute inside the Go
   Cryptographic Module, whose approved-mode implementations are the ones
   CMVP #5247 validates. SHA-1 runs in `crypto/sha1`, outside the module,
   registered `fips=no`; AES-CBC chaining is the standard library's over
   the module's AES block, without `fips=yes` (page 03).
   Evidence: E-07 to E-10.
2. The adapter relies on the validated Go module. The SP contemplates
   external calling applications: the boundary is the module
   executable code (SP 2.1), services are offered at the API level to
   calling applications (SP 2.10, 2.11), and SSPs are exchanged
   electronically with external callers (SP 9.2). The adapter can rely on
   the module when the SP's artifact, build, OE and self-test conditions
   hold in the deployment (E-08, E-09). Evidence: E-11, E-16.
3. Protocol handling for a consumer linked to an OpenSSL 3.5 library
   (the compat pair, page 04) executes in that library, not in Go; its
   cryptographic operations route to the provider, and record encryption
   goes to the module's TLS 1.3 GCM service (page 03). Evidence: E-37.
