---
last_updated: 2026-11-19
---

# 00 Auditor reading path

Read in this order.

| Step | Page | Question it answers |
|---|---|---|
| 1 | README.md | What is in scope and what is claimed |
| 2 | 01-architecture.md | What was built and where each responsibility sits |
| 3 | 02-validation-basis.md | What exactly is validated, under which certificate, with which build evidence |
| 4 | 03-crypto-service-map.md | Which algorithm runs where, which SP service covers it, what is refused |
| 5 | 05-fail-closed.md | What happens when something is missing, unsupported, or misconfigured |
| 6 | 06-interop-correctness.md | Does it interoperate and produce RFC-correct results |
| 7 | 10-evidence-manifest.md | Where each claim's evidence lives |

Supporting detail: 04 build/provenance, 07 performance, 08 operations,
09 limitations, 11 RAND pass-through semantics, 12 traceability table and
reproduction commands, 13 evidence status and release evidence.

Fast paths by role:

- Compliance reviewer: README, 02, 03, 11, 10, 12, 13.
- Security engineer: 01, 05, 06, 08.
- Deployment reviewer: 07, 08.

Summary:

- The Go Cryptographic Module v1.0.0 is CMVP #5247 validated.
- This pack shows test evidence that a Go-backed OpenSSL provider built
  per SP 5247 section 11.1 serves those validated implementations and
  fails closed everywhere else.
- The adapter relies on the validated module under the SP's conditions.
