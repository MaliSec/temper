---
last_updated: 2026-11-19
---

# 13 Evidence status, CI evidence, release evidence

Section (a) lists what is verified with evidence; section (b), what each
release produces.

## (a) Verified with evidence

| Item | Basis | Evidence |
|---|---|---|
| Adapter reliance on the validated Go module | SP text (2.1, 2.10, 2.11, 9.2) plus this deployment's exact evidence: unmodified frozen archive with the SP 11.1 digest match, approved-mode marker, integrity check and KATs at init. | E-08, E-09, E-15, E-16 |
| X509_digest(SHA256) through gofips on both ABIs | The probe (E-28) computes X509_digest under the gofips-only conf on OpenSSL 4 and 3 (OpenSSL 3.5 compat pair, sha-pinned, page 04): digest matches the pinned DER hash on both, 8 Go-dispatch lines per ABI, MD5 unfetchable, SHA256 fetchable, no-conf control same digest. Run in CI (E-29). | E-28, E-29 |
| CI execution of the provider suites | The `gofips-provider-suites` job runs every provider suite (page 06) on pull requests and pushes to main | E-29, E-34 |

## (b) Release evidence

Every release produces and attests an evidence bundle (page 10): the
suites run natively on amd64 and arm64 against the shipped `gofips.so`,
its digest, each runner's OE record, and the capture (E-41, E-43).
