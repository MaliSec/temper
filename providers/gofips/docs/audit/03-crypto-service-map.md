---
last_updated: 2026-11-19
---

# 03 Cryptographic service map

Each row is a dispatch table entry in `providers/gofips/dispatch.c`
(E-24). Each operation forwards to Go's standard library: in a
`GOFIPS140=v1.0.0` build with `GODEBUG=fips140=on`, inside the Go
module. The third column cites the approved service (SP Table 12) or
algorithm (SP Table 6, A6650/A8668) covering the Go implementation. Adapter
framing (PKCS#7 padding, RFC 8446 labels, ScalarBaseMult checks) is
not a service row (page 01). RAND: page 11.

## Approved-mode operations

Each row names the CMVP #5247 service executed in approved mode.
Fetch property contract (measured): digests and AES-GCM carry
`fips=yes`; AES-CBC and RAND rows are registered `provider=gofips`
without `fips=yes`, so a `fips=yes` fetch of AES-CBC or CTR-DRBG
fails closed (served via `provider=gofips` or a NULL query, never a
non-gofips provider). Being fetchable does not make a row an approved
service; the citation is the Go implementation's. AES-GCM and SHA-1
have their own sections below.

| Provider algorithm | Go implementation | CMVP #5247 service or algorithm | Evidence |
|---|---|---|---|
| SHA2-256 | crypto/sha256 | Message Digest; SHA2-256 (A6650, A8668) | E-01, E-03 |
| SHA2-384 | crypto/sha512 (384) | Message Digest; SHA2-384 | E-03 |
| SHA2-512 | crypto/sha512 | Message Digest; SHA2-512 | E-03 |
| SHA3-224, SHA3-256, SHA3-384, SHA3-512 | crypto/sha3 | Message Digest; SHA3, FIPS 202 (A6650, A8668) | E-39 |
| SHAKE-128, SHAKE-256 | crypto/sha3 | Extendable-Output Function; SHAKE, FIPS 202 (A6650, A8668). The caller must set the output length; there is no default. | E-39 |
| HMAC | crypto/hmac | Message Authentication; HMAC-SHA2 and HMAC-SHA3, FIPS 198-1 (A6650, A8668); 112-bit key floor | E-03, E-39 |
| HMAC keymgmt and signature | crypto/hmac | The same HMAC, reached as an `EVP_PKEY` and `EVP_DigestSign`: the form libssl uses for the TLS 1.3 PSK binder in session resumption. Same digests and key floor; sign only, input up to 1 MiB. | E-20 |
| HKDF | crypto/hkdf (module fips140/hkdf) | KDA HKDF SP 800-56Cr1 with SHA-2 or SHA-3 (A6650, A8668) | E-03, E-39 |
| PBKDF2 | crypto/pbkdf2 | Password-Based Key Derivation; PBKDF, SP 800-132 (A6650). Served within the SP's approved conditions: salt of 128 bits or more, derived key of 112 bits or more, HMAC with SHA-2 or SHA-3, and at least one iteration. Outside these, PBKDF2 is refused (SP Table 8 lists short salts and keys as non-approved), including OpenSSL's SHA-1 default. Passwords of any length are accepted, as SP 800-132 sets no minimum. | E-39 |
| EC keymgmt (P-256, P-384) | crypto/ecdh, crypto/ecdsa | Key Generation; ECDSA KeyGen, FIPS 186-5 (A6650, A8668). Named curves only: explicit curve parameters are refused. | E-03, E-40 |
| ECDH (P-256, P-384) | crypto/ecdh | Key Agreement; KAS-ECC-SSC SP 800-56Ar3 (A6650, A8668) | E-03, E-40 |
| ECDSA (P-256, P-384) | crypto/ecdsa SignASN1, VerifyASN1 | Digital Signature; ECDSA SigGen/SigVer, FIPS 186-5 (A6650, A8668), with SHA-256, SHA-384 or SHA-512; one-shot and streaming (EVP_DigestSign/VerifyUpdate) | E-03, E-39, E-40 |
| RSA keymgmt | none (holds the public key) | No service of its own: imports RSA public keys (under the RSA and RSA-PSS names) for verification. Private keys, key generation and keys with RSA-PSS restrictions are refused. | E-40 |
| RSA signature (verify only) | crypto/rsa VerifyPKCS1v15, VerifyPSS | Digital Signature; RSA SigVer, FIPS 186-5 (A6650: PKCS#1 v1.5 and PSS, moduli 2048, 3072 and 4096, e = 65537 tested). Refused where the module marks the key non-approved (`rsa.checkPublicKey`: a modulus under 2048 bits or of odd length, e of 2^16 or less) and for a PSS salt longer than the hash (FIPS 186-5 section 5.4). | E-40 |

## AES-GCM

Served through the module's TLS 1.3 and TLS 1.2 GCM services, labelled
fips=yes, for TLS record protection only. TLS 1.2: see "TLS 1.2" below.

### Served through the module's TLS 1.3 GCM service

| Provider algorithm | Go implementation | Service | Evidence |
|---|---|---|---|
| AES-256-GCM, AES-128-GCM | The module's TLS 1.3 GCM (`crypto/internal/fips140/aes/gcm`, `NewGCMForTLS13`), reached through the linkname hook `crypto/tls.aeadAESGCMTLS13` (`gcm_tls13.go`) | Authenticated encryption; AES-GCM with the module's TLS 1.3 IV mechanism (SP 2.7). The module learns the static IV from the first record and refuses any nonce whose counter does not increase. Rows carry `fips=yes`, scoped by the SP to TLS 1.3 use (below). | E-30, E-31, E-37 |

Measured (E-37):
- The path runs under `GODEBUG=fips140=only`, which rejects non-approved
  operations; the general `cipher.NewGCM` path is rejected there.
- The module itself refuses a repeated record counter with the adapter's
  own check bypassed.
- Real TLS 1.3 connections through libssl complete in both directions
  against the default provider.

What the Security Policy says (E-16):
- SP 2.7 lists `NewGCMForTLS13` among the APIs the module implements
  to generate AES-GCM IVs: "enforced construction of deterministic
  nonces as specified in RFC 8446, Section 5.3, complying with IG C.H
  Scenario 1.a". That is the function this path ends in.
- The SP's non-approved entry for AES GCM is "Using arbitrary nonces
  for encryption". That is `cipher.NewGCM`, which the provider does not use.
- SP 2.1 gives the module's purpose as providing cryptographic
  functionality "to the Go standard library and other Go applications",
  and SP 2.11 says the module "only offers cryptographic services to
  calling applications and does not contain full implementations of
  industry protocols". The SP sets no condition on which code calls
  `NewGCMForTLS13`. The provider calls `crypto/tls`'s constructor,
  which calls it: standard-library code calling the module's named API.
- SP 2.7 sets one condition on use: IVs from `NewGCMForTLS13` "should
  be used in the context of the respective protocols".

Reading: the service is the approved one. The `crypto/tls` function is
unexported and kept linkable for outside users (go.dev/issue/67401), a Go
API-stability dependency tracked on page 09.

Scope: the SP's condition is the TLS 1.3 protocol context. OpenSSL's
libssl is a TLS 1.3 implementation and its record layer is that
context. The provider cannot tell libssl's record layer from another
caller, so a non-TLS caller gets the same rules (and the limits in the
refused table) but is outside the SP's condition and outside the
claim. The rows carry `fips=yes` on that basis:
the label states what the SP approves, TLS 1.3 record protection. A
cipher row cannot be limited to TLS callers, so the label does not
make application-level GCM approved; that use is outside the claim
and is listed as a limitation (page 09).

## Served, not approved

| Provider algorithm | Go implementation | Status | Evidence |
|---|---|---|---|
| SHA-1 | crypto/sha1, outside the Go Cryptographic Module (the module has no SHA-1) | Registered `fips=no`; description says "NOT approved" and cites no certificate. For non-security uses applications cannot avoid (WebSocket handshakes, ETags). A `fips=yes` fetch fails. Not accepted by HMAC, HKDF or ECDSA. Under `GODEBUG=fips140=only` Go refuses it and the provider fails cleanly at init. | E-01, E-14 |
| AES-256-CBC, AES-128-CBC | stdlib CBC over the module's AES block primitive | Registered without `fips=yes`. Encrypts TLS session tickets: OpenSSL's ticket callback uses AES-256-CBC, Node's AES-128-CBC. AES-CBC is SP 800-38A (A6650, A8668). | E-18, E-20 |

## Composite operations

| Provider algorithm | Composition | Evidence |
|---|---|---|
| TLS13-KDF | The module's HKDF service plus RFC 8446 section 7.1 label framing; not the CAVP TLS13-KDF service row (module-internal; dispatch.c states this). | E-03 |

## TLS 1.2

| Provider algorithm | Go implementation | Service | Evidence |
|---|---|---|---|
| TLS1-PRF | The module's TLS 1.2 KDF (`crypto/internal/fips140/tls12.PRF`), reached through `crypto/tls.prf12` | Key Derivation; TLS 1.2 KDF, SP 800-135 (CAST in SP Table 20), with SHA-256, SHA-384 or SHA-512. The classic master secret is refused: the extended master secret (RFC 7627) is required. Results equal the default provider's. | E-42 |
| AES-128-GCM, AES-256-GCM in TLS 1.2 record mode | The module's TLS 1.2 GCM (`NewGCMForTLS12`), reached through `crypto/tls.aeadAESGCM` | Authenticated encryption with an approved IV mechanism (SP 2.7: "enforced construction of deterministic nonces as specified in RFC 5288"). The provider numbers each sealed record's explicit nonce from zero; the module refuses one that does not increase. | E-42 |

Both `crypto/tls` functions are unexported and carry no linkname marker,
so the provider is linked with `-ldflags=-checklinkname=0` (page 09). Only
ECDHE suites with AES-GCM are served; CBC record mode is refused.

## Refused operations

| Operation | Status | Reason | Evidence |
|---|---|---|---|
| GCM nonce reuse within a key instance | Refused | The module's record counter must strictly increase: the same nonce again, an earlier nonce, or a nonce with a different fixed prefix is refused. A copied ctx shares the instance; re-keying a ctx with the same key keeps it. | E-30 (T10, T11), E-31, E-37 |
| Streaming GCM encrypt (multi-update data) | Refused | Go seals a whole message in one call; per-update sealing would reuse the keystream | E-30 (T1) |
| GCM decrypt with the tag set after the data | Refused at final, nothing written | Go releases plaintext only after verifying the tag, and EVP gives the GCM final call no output space. Set the tag before the data (the TLS record order; Node `setAuthTag` before `update`). | E-30 (T2) |
| GCM tag shorter than 96 bits, or a truncated tag for decryption | Refused | SP 5247 Table 6 tag lengths are 96 to 128 bits; the module's TLS 1.3 GCM verifies full 16-byte tags only | E-39 |
| HKDF or TLS13-KDF with an unknown mode | Refused | Modes are EXTRACT_AND_EXPAND, EXTRACT_ONLY, EXPAND_ONLY (names or 0-2), as the default provider | E-39 |
| RSA private-key operations (sign, decrypt, key generation) and RSA encryption | Refused | The key manager imports public keys only; there are no sign or encrypt entry points. A refused private key may survive as a libcrypto legacy key object; every operation on it fails. | E-40 |
| RSA verification with a modulus under 2048 bits or of odd length, or e of 2^16 or less | Refused | The module marks these keys non-approved | E-40 |
| RSA-PSS with a salt longer than the hash, or salt length "max" | Refused | FIPS 186-5 section 5.4; "auto" accepts only a salt of the digest length | E-40 |
| RSA-PSS-restricted keys | Refused at import | The restrictions would not be enforced | E-40 |
| PKCS#1 v1.5 verification with an RSA-PSS key | Refused | An RSA-PSS key is for PSS only | E-40 |
| X25519 | Refused at fetch | Only P-256 and P-384 ECDH served | E-13 |
| P-521, explicit EC curve parameters | Refused at keygen and import | Named P-256 and P-384 only; a chain with an explicit-parameter key fails verification | E-40 |
| ChaCha20-Poly1305 | Refused at fetch | Not registered | E-13 |
| TLS 1.1 and older | Blocked at protocol layer | No TLS 1.0/1.1 PRF (MD5-SHA1) | E-42 |
| TLS 1.2 CBC suites | Refused when the record layer is set up | TLS CBC record mode (MAC-then-encrypt) is not served | E-42 |
| TLS 1.2 without the extended master secret | Refused at the master secret | RFC 7627 required | E-42 |
| MD5 | Refused. OpenSSL 4: not registered, so a fetch fails. OpenSSL 3: a refused row is registered, so a fetch resolves to gofips and every use fails, as Wolfi's OpenSSL 3.6 base would otherwise serve MD5 (page 06) | Positive control proves the default would serve it | E-05, E-06, E-45 |
| SHA-224, SHA-512/224, SHA-512/256 | Refused at fetch | Not registered | E-24 |
| HMAC signature over more than 1 MiB, with a key under 112 bits or a SHA-1 digest | Refused | The signature buffers its input (EVP_DigestSignFinal duplicates the context); the key and digest rules are the HMAC MAC's | E-42 |
| SHAKE with no output length | Refused at final | FIPS 202 has no default output length | E-39 |
| PBKDF2 with a salt under 128 bits, a key under 112 bits, HMAC-SHA-1, no digest, or iterations of 0 or less | Refused | Outside SP 800-132's approved conditions (SP Table 8) | E-39 |

Boundary of the GCM nonce rule (not a refusal): a brand-new ctx given
the same key bytes is a new key instance to the module, as it is to the
default provider, so the same nonce is accepted there (E-30, T10 note).
TLS derives a fresh key per connection and never does this.

X509_digest(SHA256) through gofips is verified on both ABIs (E-28):
the digest executes in Go, with fail-closed controls.
