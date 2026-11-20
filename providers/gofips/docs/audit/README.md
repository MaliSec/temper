---
last_updated: 2026-11-19
---

# GoFIPS provider audit evidence pack

## Document control

| Field | Value |
|---|---|
| Repository | github.com/MaliSec/temper |
| Evidence | Attached to each release as an attested bundle, produced from the release commit (page 10) |
| Pack location | providers/gofips/docs/audit/ |
| Audience | Security and compliance engineers |

## Scope

The `providers/gofips` directory of this repository: an OpenSSL provider
(`gofips.so`) forwarding cryptographic operations to the Go
Cryptographic Module (CMVP #5247). Not covered: the rest of Temper.

## Status definitions

| Status | Meaning |
|---|---|
| Verified | A release's evidence bundle, a source file or a primary source supports the statement (evidence ID). |
| Release evidence | Produced and attested by each release (page 13). |

## Basis

The adapter relies on the validated Go Cryptographic Module v1.0.0 under
CMVP certificate #5247, on the terms of that certificate (page 02).

## Navigation

| Page | Content |
|---|---|
| 00-reading-path.md | Reading path by role |
| 01-architecture.md | The system in one diagram, bounded claims |
| 02-validation-basis.md | CMVP #5247, SP 5247, frozen module, self-tests, OEs |
| 03-crypto-service-map.md | Service map, AES-GCM, TLS 1.2, refused operations |
| 04-build-provenance.md | Build, hashes, ELF facts, compat pair |
| 05-fail-closed.md | Every negative case with evidence |
| 06-interop-correctness.md | TLS gates, interops, KAT, CI |
| 07-performance.md | Measured deltas and limits |
| 08-operating-guide.md | Config matrix, checklist, incident rule |
| 09-limitations.md | Limitations |
| 10-evidence-manifest.md | Evidence IDs |
| 11-rand-semantics.md | RAND pass-through semantics |
| 12-traceability-review.md | Traceability table, reproduction commands |
| 13-release-evidence.md | Evidence status and release evidence |

## Evidence status at a glance

Full list on page 10. Headline rows:

- Module validation: E-08, E-09, E-15, E-16
- Provider crypto and exclusive routing: E-01 to E-06, E-13
- Integration evidence: amd64 E-14, E-19; arm64 native in CI (E-41), qemu
  functional record (E-12)
- TLS 1.3 GCM: E-37; TLS 1.2: E-42 (page 03)
- RAND: E-09, E-10
- SSL_CTX_new: E-27
- X509_digest: E-28
- CI suites: E-29; release suites against the shipped provider: E-43

## Acronyms

CMVP: Cryptographic Module Validation Program (NIST). CAVP: algorithm
validation. SP: Security Policy. OE: Operational Environment. DRBG:
Deterministic Random Bit Generator. KAT: Known-Answer Test. IKM: Input
Keying Material. TLS: Transport Layer Security.
