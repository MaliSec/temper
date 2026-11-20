---
last_updated: 2026-11-19
---

# 02 Validation basis

## The certificate

| Field | Value | Source |
|---|---|---|
| Module | Go Cryptographic Module v1.0.0 | [CMVP certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247) (E-15) |
| Standard | FIPS 140-3 | same |
| Status | Active; sunset 2031-04-26 | same |
| Overall level | 1 (software, MultiChipStand) | same |
| Caveat | "When operated in approved mode. No assurance of the minimum strength of generated SSPs... established with externally loaded SSPs." | same |
| CAVP certificates | A6650, A8668 | SP 5247 Tables 6 and 7 |

## The Security Policy

SP 5247 (non-proprietary security policy for v1.0.0 and v1.0.1), from
https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf
(E-16, sha256 `2dfcf09554a8f045d6a6326a1c66ac4c079f3fc27cee90ed27262c60c75b4478`).

Key statements quoted from the SP:

- SP 2.1: the boundary is the entire Go Cryptographic Module executable
  code; any calling application is the designed consumer.
- SP 2.10 and 2.11: services are offered at the API level to calling
  applications; the module does not implement full protocols.
- SP 9.2 (Table 15): SSPs are exchanged electronically with external
  calling applications.
- SP 5.3: the module source is distributed under a BSD-style license; the
  build toolchain must be the one from the distribution containing the
  archive.
- SP 5.1: integrity is HMAC-SHA2-256 over all `fips.o` components, checked
  automatically at power-up; failure terminates the module.
- SP 11.1: build from the unmodified archive `v1.0.0-c2097c7c.zip`, digest
  `daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b`, with
  `GOFIPS140=v1.0.0`; verify via `go version -m` showing
  `build GOFIPS140=v1.0.0-c2097c7c`.

## Frozen module in this build

The build used the toolchain-embedded archive
`$GOROOT/lib/fips140/v1.0.0-c2097c7c.zip` (Go 1.26.11 toolchain,
linux/amd64). Its measured sha256 equals the SP 11.1 required digest
exactly (E-08), and nothing in this project modifies it.

## Build metadata

`go version -m gofips.so` shows `build GOFIPS140=v1.0.0-c2097c7c`,
`build -tags=fips140v1.0`, `build DefaultGODEBUG=fips140=on` (E-08): the
SP 11.1 approved-mode marker verbatim.

## Integrity self-test and KATs

At init the runtime runs the HMAC-SHA2-256 integrity check over `fips.o`
and the self-tests (the integrity test, SP Table 19; the conditional
self-tests, SP Table 20), including the CTR DRBG Known-Answer Test (KAT: a
comparison against a pre-computed value) per SP 800-90A and IG 10.3.A.
Failure aborts the process. Observed: the process completes with
`fips140.Enabled()=true` under `GODEBUG=fips140=on`, and reports false
with the mode off (E-08, E-09).

## Unmodified module boundary

The adapter calls the module through Go's crypto APIs (`crypto/sha256`,
`crypto/rand`, `crypto/hmac` and the others, which reach
`crypto/internal/fips140` in a FIPS build) and three unexported
`crypto/tls` functions for TLS record protection and the TLS 1.2 KDF
(`aeadAESGCMTLS13`, `aeadAESGCM`, `prf12`; pages 03 and 09). No `fips.o`
binary is modified and no module-internal symbol is called directly (E-24
source review; E-07 counters prove the calls land in the module).

## Tested OE versus deployment

SP Table 3 tested OEs include Red Hat Enterprise Linux 9 on x86-64 and on
Ampere Altra arm64, and Amazon Linux 2023 on AWS Graviton4; SP Table 4
vendor-affirmed OEs include Linux 3.10+ through 7.x on x86-64 and on
ARMv7, ARMv8 and ARMv9. The amd64 evidence ran natively on Linux x86-64.
The arm64 evidence runs natively on Linux arm64 in CI, on GitHub's
`ubuntu-24.04-arm` runners, which record their CPU alongside the logs
(E-41). Whether a given deployment matches a listed OE is for the deployer
to establish.

The capture also runs arm64 under qemu user-mode emulation (E-12, E-04),
which shows functional correctness only.

Every "validated" statement here applies to the Go module alone, in
approved mode, on the terms of #5247; the adapter relies on it when the
SP's conditions hold in the deployment (E-08, E-09).
