# Node.js FIPS runtime base image

The `node` image with the gofips OpenSSL provider. The cryptographic
operations `node:crypto`, WebCrypto and `node:tls` perform through
OpenSSL's EVP interface run in the Go Cryptographic Module (CMVP #5247),
except SHA-1 and AES-CBC (see "Served"); the few Node APIs that would
compute outside it throw (see "APIs that bypass the provider"). The
default and legacy OpenSSL providers are not loaded, so an operation gofips
does not serve fails instead of falling back.

Everything else (packages, versions, user, environment) is the
`node` image; `make test` keeps them identical.

## FIPS claim

The image relies on CMVP #5247 for the operations listed as served below.
gofips passes calls to the validated module unmodified. What the reliance
rests on, and the evidence for each condition, is in the gofips audit pack
([providers/gofips/docs/audit](../../providers/gofips/docs/audit/README.md)).

The configuration that makes this hold is set in the image:

- `OPENSSL_CONF=/etc/ssl/openssl-gofips.cnf` loads gofips and `base` only.
- `GODEBUG=fips140=on` runs the Go module in approved mode.

Changing either one, or loading another provider (including with
`--openssl-legacy-provider`), takes the image outside the claim.

## Served

| Area | Algorithms |
|---|---|
| Hashes | SHA-256, SHA-384, SHA-512, SHA3-224/256/384/512, SHAKE128, SHAKE256 |
| MACs | HMAC with a SHA-2 or SHA-3 hash (keys of 112 bits or more) |
| Key derivation | HKDF (see "APIs that bypass the provider"), PBKDF2 (salt of 128 bits or more, derived key of 112 bits or more, SHA-2 or SHA-3) |
| Elliptic curve | P-256 and P-384: key generation, ECDH, ECDSA sign and verify (SHA-256, SHA-384, SHA-512) |
| RSA | Signature verification only: PKCS#1 v1.5 and PSS, SHA-256/384/512, keys of 2048 bits or more |
| Ciphers | AES-128-GCM, AES-256-GCM; AES-128-CBC, AES-256-CBC (outside the claim: registered without `fips=yes`) |
| Random | `crypto.randomBytes`, `crypto.randomUUID`, WebCrypto `getRandomValues` |
| TLS | TLS 1.3, and TLS 1.2 with AES-GCM and the extended master secret; see below |

SHA-1 is served for non-security uses (WebSocket handshakes, ETags) and is
not approved. AES-GCM is approved for TLS records; application use of
`createCipheriv('aes-256-gcm')` works but is outside the claim, and its nonce
check is per cipher object, not per key. AES-256-CBC and AES-128-CBC
encrypt TLS session tickets and are outside the claim.

## APIs that bypass the provider

These Node APIs call libcrypto's built-in low-level code instead of EVP, so
their work would not reach gofips. In this image they throw
`ERR_TEMPER_FIPS_UNAVAILABLE`:

- `createDiffieHellman`, `getDiffieHellman`, `createDiffieHellmanGroup`
  and the `DiffieHellman` classes (finite-field DH). Use ECDH.
- `crypto.generatePrime`, `crypto.checkPrime` and their `Sync` forms.
- `ECDH.prototype.setPrivateKey` and `ECDH.convertKey`, and any use of an
  EC private key given as a JWK or as a raw scalar
  (`format: 'raw-private'`), which libcrypto rebuilds from the scalar:
  `createPrivateKey`, `createPublicKey`, `sign`, `verify`,
  `createSign().sign`, `createVerify().verify`, the public and private
  encrypt and decrypt functions, `encapsulate` and `decapsulate`, and
  WebCrypto `importKey('jwk', …)` and `unwrapKey('jwk', …)` for ECDSA and
  ECDH. Import EC private keys as PKCS#8 (DER or PEM) instead, which goes
  through the module.

A preloaded guard (package `temper-node-fips`) does this, through
`NODE_OPTIONS=--require=/usr/lib/node-fips/guard.js` in the image's
environment. Node processes and worker threads that inherit the
environment load it. One started with its own environment (a `Worker` or
child process given `env`) or an application that sets `NODE_OPTIONS`
itself must keep that `--require`, or the guard is not loaded there and
these APIs compute outside the module again. Check with
`globalThis[Symbol.for("temper.node-fips.guard")]`.

The guard covers these APIs as Node exposes them. It stops ordinary use,
not code written to get around it (for example by reaching Node's
internals), and native addons that call libcrypto directly are outside
the claim.

`NODE_OPTIONS` also sets `--tls-cipher-list` to the suites gofips serves,
so a Node TLS server or client never selects a suite the provider would
refuse. An application that replaces `NODE_OPTIONS` without it still fails
closed on such a suite, but may fail to connect where a served suite was
available.

HKDF (`hkdfSync`, WebCrypto HKDF): Node computes the extract step itself
with HMAC, which runs in the module, keyed by the salt, then asks gofips
only for the expand step. So the provider's 112-bit minimum on the input
key does not apply: use secrets of at least 112 bits, as SP 5247 requires
for HKDF. A non-empty salt shorter than 14 bytes fails, because it becomes
the HMAC key.

## Refused

These fail with an error such as `ERR_OSSL_EVP_UNSUPPORTED`:

- MD5, MD4, RIPEMD-160, SHA-224, SHA-512/256, BLAKE2.
- RSA private keys (signing, decryption, key generation) and RSA encryption.
- RSA verification with a key under 2048 bits or a public exponent below
  65537, or PSS with a salt longer than the hash (all non-approved in the
  module).
- Ed25519, X25519, P-521.
- ChaCha20-Poly1305, AES-CTR, scrypt.
- PBKDF2 with a short salt or key, or with SHA-1; HMAC with a key under
  112 bits.
- TLS 1.1 and below; TLS 1.2 CBC suites, and TLS 1.2 without the extended
  master secret.

## TLS

TLS 1.3, and TLS 1.2 with AES-GCM and the extended master secret
(RFC 7627), with P-256 or P-384 key exchange and server certificates that
are ECDSA (P-256, P-384) or RSA (2048 bits or more), in chains signed with
ECDSA or RSA (PKCS#1 v1.5 or PSS) and SHA-2. Most public HTTPS services meet
this; the smoke test connects to packages.wolfi.dev (TLS 1.3) and
registry.npmjs.org (TLS 1.2) with verified chains. Session tickets and
resumption work, as client and as server.

A connection fails when the server:

- supports only TLS 1.1 or older, or TLS 1.2 without AES-GCM or without
  the extended master secret;
- presents a P-521 or Ed25519 certificate, or a chain with a SHA-1
  signature, an RSA key under 2048 bits, or an RSA public exponent below
  65537;
- requires a client certificate with an RSA key (this image can hold only
  ECDSA private keys).

## Use

Install dependencies in a `node-builder` stage, which has npm and the
default OpenSSL provider, and copy the result into this image, which has
neither:

    FROM ghcr.io/malisec/temper/node-builder@sha256:<digest> AS build
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci --omit=dev
    COPY . .

    FROM ghcr.io/malisec/temper/node-fips@sha256:<digest>
    COPY --from=build --chown=65532:65532 /app /app
    ENTRYPOINT ["/usr/bin/node", "/app/server.js"]

Check a container's provider set:

    docker run --rm --entrypoint /usr/bin/node <image> -e \
      'console.log(require("fs").readFileSync("/proc/self/maps","utf8").includes("gofips.so"))'

`tests/smoke-node-fips.js` checks the served and refused lists above, except
the extended master secret requirement and the RSA verification limits,
which the provider suites check.

## Tags

Two lines are published in this repository: 26 (active LTS, this
directory) and 24 (maintenance LTS, `images/node-fips-24`).

- `node-fips:26` follows the newest release on the 26 line (forward only).
- `node-fips:24` follows the newest release on the 24 line (forward only).
- `node-fips:26-YYYY.MM.DD`, `node-fips:24-YYYY.MM.DD` and
  `node-fips:YYYY.MM.DD` (the 26 line) never move.
- `node-fips:latest` follows the newest release of the 26 line.

Pin a digest for reproducible builds.
