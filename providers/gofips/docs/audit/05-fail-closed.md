---
last_updated: 2026-11-19
---

# 05 Fail-closed security case

Design rule: gofips is the only crypto provider; unregistered
fetches fail; init refuses with Go FIPS mode off (E-24, E-14). SHA-1 is
registered `fips=no`; AES-CBC and RAND carry no `fips=yes` (page 03).
GCM detail is on page 03.

## Negative cases

| # | Case | Observed | Evidence |
|---|---|---|---|
| N1 | MD5 under `provider=gofips` | no digest computed (OpenSSL 3: the refused row fails at init; OpenSSL 4: not fetchable); default serves | E-01, E-45 |
| N2 | MD5 fetch, default absent | createHash('md5') throws | E-14 |
| N3/N4 | ChaCha20 fetch / RSA key generation | refused | E-03 |
| N5 | TLS 1.2 CBC-only or non-EMS peer; TLS 1.1 client | refused | E-42, E-13 |
| N6-N8 | ChaCha ciphers / X25519 / RSA-only sigalgs (no RSA signing key) | refused | E-13 |
| N9/N10 | Module missing / conf without a provider | CSPRNG assert rc=134/139 | E-14 |
| N11 | GODEBUG=fips140=off | init refuses; no boot | E-14 |
| N12/N13 | Tampered verify / compat MD5 | refused / failed | E-03, E-12, E-14 |
| N14 | Default-served legacy-ctor derive | unsupported | E-35 |
| N15 | GCM nonce repeated on a ctx, or through a copy of it | refused (module record counter) | E-30, E-31, E-37 |
| N16 | SHA-1 fetched with `fips=yes`; HMAC with SHA-1 | refused | E-01, E-14 |
| N17 | SHA-1 under `GODEBUG=fips140=only` | fetch succeeds, init fails cleanly, no hang | E-37 (strict-mode runs) |
| N18 | PBKDF2 outside SP 800-132 (short salt or key, SHA-1, no digest, iterations of 0 or less); SHAKE with no output length | refused | E-39 |
| N19 | RSA: private-key operations, encryption, a non-approved key, a PSS salt longer than the hash; EC: P-521, explicit curve parameters | refused | E-40 |

## ABI paths and the exclusive-configuration boundary

Both OpenSSL generations (4.0.3 in Node, the 3.5 compat pair) load the
same `.so` and fail closed on unregistered algorithms (E-01, E-38). Supported:
the gofips-only OPENSSL_CONF (gofips + base). Every fetch there, legacy
constructor included, routes into gofips or fails closed (E-35, both
ABIs). Outside it libcrypto resolves a NULL-propq fetch to the default
provider, as it does for the genuine FIPS provider (E-36). Claims apply
only to the exclusive config.

## Panic containment across the export surface

Every dispatch-wired export is in one of three classes. `guardcheck.sh`
fails CI on an export it cannot classify; the capture in each release's
evidence bundle has the counts (`guardcheck-classification.log`):
- opGuard (panic -> refusal, never success): every wired
  export returning C.int.
- Pointer/handle/void class: unguarded. These return handles,
  pointers or nothing; a panic in one aborts the host, because a panic
  cannot unwind through a C frame. The claim for this class is input
  hygiene, not panic recovery: each body validates inputs and fails
  closed (0/nil) on a hostile handle; panictest.c drives every
  family's hostile shapes (E-34). Unwired:
  gofips_digest_gettable_params (always nil, breaks OpenSSL 3.0.x).
- C-implemented: the SHA-3 and SHAKE newctx and get_params
  wrappers and the TLS capability callbacks in dispatch.c (no Go
  source).

Process-death tests cover the NULL-buffer BN shape (audreg bn-null/a) and
13 parameter shapes (paramshape13.c, differential against the default
provider); the gofips rc=0 refusal holds on every ABI. The parameter
get/set helpers check the NULL data pointer before any unsafe.Slice,
report the needed size on a size query and fail without writing on a
short buffer, matching the default provider; zero-length data stays
legitimate. 32-bit-natural keys report return_size 4, size_t keys 8
(probe_bits.c).

## Locks and refusals

A panic recovered by opGuard does not release a mutex, so a ctx lock
held across a hash call that panics would block that ctx forever. Hash
calls under a ctx lock
go through `withLock`, which releases on every exit. GCM refusals are
explicit adapter errors, not panics; if the module itself panics, that
key instance refuses everything afterwards.

## Configuration assumptions

1. `GODEBUG=fips140=on` is set.
2. The conf's module path points at the mounted `.so` (checked at init).
