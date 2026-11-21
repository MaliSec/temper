---
last_updated: 2026-11-19
---

# 09 Limitations

## Validation status

- The adapter (`gofips.so`) relies on the validated Go module when the
  SP's conditions hold: digest match and build marker (E-08), integrity
  and KATs at init (E-09), a listed OE (page 02). Every "validated"
  statement applies to the Go module alone, in approved mode, on the
  terms of #5247 (E-11, E-16).
- The OpenSSL RAND op is a pass-through with no-op instantiate/reseed and
  no caller entropy forwarding (page 11); the module's DRBG state is not
  exposed through the public Go API, and the module handles entropy
  internally (E-10).

## AES-GCM and SHA-1

- The TLS 1.3 GCM path relies on `crypto/tls.aeadAESGCMTLS13`, an
  unexported function Go keeps linkable for existing outside users. It
  is not public Go API, so a toolchain change could alter or remove it.
  The function it calls, `NewGCMForTLS13`, is an approved IV API in SP
  2.7 (page 03).
- TLS 1.2 relies on `crypto/tls.prf12` and `crypto/tls.aeadAESGCM`, which
  call the module's TLS 1.2 KDF and `NewGCMForTLS12`. They carry no
  linkname marker, so the provider is linked with
  `-ldflags=-checklinkname=0`, which disables that linker check for the
  whole provider build. A toolchain that changes either function fails
  E-42 in CI.
- The SP conditions that API on use "in the context of the respective
  protocols". The claim therefore covers TLS record protection.
  Application-level GCM through the provider is outside it, even though
  the GCM rows carry `fips=yes`: a cipher row cannot be limited to TLS
  callers.
- GCM is served for the TLS record patterns. A multi-update encrypt
  is refused, and a decrypt with the tag set after the data is refused.
  Both work on the default provider. Application-level GCM that streams,
  or whose format puts the tag at the end, does not work.
- GCM nonce uniqueness is per key instance. A brand-new ctx given the
  same key bytes starts a new instance (page 03).
- SHA-1 is served outside the validated module and is not approved. A
  consumer that needs SHA-1 cannot run under `GODEBUG=fips140=only`,
  because Go refuses SHA-1 there.
- MD5 is never served: unregistered under OpenSSL 4, and a refused row
  under OpenSSL 3 (page 06). Applications that call MD5 through Node's
  crypto fail on that call.

## RSA, P-384, PBKDF2 and SHA-3

- RSA is verification only. Applications cannot hold an RSA private key,
  so a TLS server or client certificate must use an ECDSA key.
- RSA verification refuses keys the module marks non-approved (a modulus
  under 2048 bits or of odd length, e of 2^16 or less) and PSS salts longer
  than the hash. PSS with salt length "auto" accepts only a salt of the
  digest length, because Go cannot report the salt length it detected; an
  explicit salt length of 0 is refused for the same reason (E-40).
- A private RSA key, or an EC key with explicit curve parameters, that
  gofips refuses at import can remain a libcrypto legacy key object.
  Every cryptographic operation on it fails, and a certificate chain
  containing an explicit-parameter key fails verification (E-40).
- PBKDF2 refuses requests outside SP 800-132's approved conditions. OpenSSL
  defaults the PBKDF2 digest to SHA-1, so callers must set a SHA-2 or SHA-3
  digest (E-39).
- SHAKE needs an explicit output length; OpenSSL 4.0 has no default (E-39).
- TLS 1.2 needs AES-GCM and the extended master secret: a peer that
  offers only CBC suites, or no extended master secret, cannot connect
  (E-42).
- With OpenSSL 3.0 under `GODEBUG=fips140=only`, certificate chains do not
  verify: Go refuses SHA-1, libcrypto then has no certificate fingerprints,
  and OpenSSL 3.0.13 builds no chain without them. OpenSSL 3.5, 3.6.5 and
  4.0.3 do (E-38, note 3). The supported configuration (`fips140=on`) is not
  affected.
- OpenSSL's deprecated `HMAC_CTX` API composes HMAC in libcrypto from
  digest calls, outside the module, without the provider's key floor.
  CPython's `hmac` module uses it; the python-fips image replaces that
  module with one that computes every HMAC through the provider
  (`packages/python-fips-3.14`, `packages/python-fips-3.13`).
  Other callers of `HMAC_CTX` are outside the claim.
- The claim covers operations that reach the provider through OpenSSL's EVP
  interface. libcrypto's deprecated low-level APIs compute in libcrypto
  itself: DH (`DH_generate_key`), EC (`EC_KEY_generate_key`,
  `ECDH_compute_key`, `ECDSA_do_sign`, `EC_POINT_mul`) and BIGNUM prime
  generation. In node-fips these back `createDiffieHellman` and
  `getDiffieHellman`, `generatePrime` and `checkPrime`, and
  `ECDH.setPrivateKey` and `ECDH.convertKey`; a preloaded guard
  (`temper-node-fips`, via `NODE_OPTIONS`) makes those APIs throw. An
  application that replaces `NODE_OPTIONS` without the guard's `--require`
  removes it (images/node-fips/README.md). Native addons that call these
  libcrypto APIs directly are outside the claim.
- Node computes HKDF-Extract itself with one-shot HMAC (in the module) and
  asks the provider only for HKDF-Expand, so the provider's 112-bit minimum
  on the input key does not apply to Node's `hkdfSync` and WebCrypto HKDF.
  Callers must use secrets of at least 112 bits (SP 5247 Table 8).
- AES-GCM tags are read and set at 96 to 128 bits only; decryption needs
  the full 16-byte tag, because the module's TLS 1.3 GCM verifies only full
  tags.

## Platform and build

- arm64: native evidence comes from GitHub's arm64 runners (E-41), not
  from the capture host, which is amd64. arm64 performance figures come
  from the same runs, on shared hosted runners, and vary more than the
  amd64 capture (page 07). The qemu evidence (E-12) is functional only.
- Explicitly empty HKDF salt on OpenSSL below 3.5: gofips treats an empty
  salt as present, as OpenSSL 3.5+ does. The 3.0 default provider ignores
  an empty salt, so a direct EVP_KDF caller on 3.0 gets a different result
  from gofips than from the default provider. TLS 1.3 handshakes are
  unaffected (E-38).

## Go runtime caveats

- A Go release can change GODEBUG defaults or fips140 switch semantics;
  the exclusive-FIPS gate is the build stamp plus `crypto/fips140.Enabled()`
  cross-checked against `GODEBUG` (E-24). Re-verify the gate on any
  toolchain upgrade.

## CI

- CI runs the provider suites on pull requests and pushes to main (job
  `gofips-provider-suites`, E-29), and each release runs them against the
  shipped provider (E-43).
