---
last_updated: 2026-11-19
---

# 11 RAND semantics

The OpenSSL RAND operation is the one surface where the adapter's mapping
has visible semantic gaps.

## What the path is

The provider's RAND operation passes through to Go's public
`crypto/rand.Read`. In a `GOFIPS140=v1.0.0` build with
`GODEBUG=fips140=on`, that call reaches the Go Cryptographic Module's
SP 800-90A Rev. 1 CTR DRBG: the toolchain source
(`crypto/rand/rand.go`, Go 1.26.11) selects
`crypto/internal/fips140/drbg.Read` when `fips140.Enabled` (E-10). The
CTR DRBG Known-Answer Test runs at init and aborts the process on
failure.

This is the module's approved DRBG service, not an OS CSPRNG fallback.
The OS entropy source feeds the DRBG, which is how the module is designed
to receive it (SP 5247 section 2.8: the entropy source sits inside the
tested perimeter but outside the cryptographic boundary).

## The semantic boundary

The adapter maps the OpenSSL RAND operation onto this path as follows
(E-10):

| OpenSSL RAND op | Adapter behavior |
|---|---|
| instantiate / uninstantiate | acknowledged as no-ops: Go's DRBG self-manages its lifecycle |
| reseed (with caller entropy or additional input) | no-op: no public Go API forwards those inputs to the module's DRBG |
| generate | forwarded to `crypto/rand.Read`, which reaches the module's DRBG in FIPS mode |
| strength | reported as 256; the caller's requested strength is not negotiated |
| reseed interval | governed by Go's DRBG policy, not the caller's parameters |

## Statement

In FIPS mode, RAND output is produced by the #5247 module's SP 800-90A
DRBG through the public crypto/rand path. The OpenSSL RAND operation is a
pass-through to it; the DRBG's state is not exposed through the public Go
API (E-10).
