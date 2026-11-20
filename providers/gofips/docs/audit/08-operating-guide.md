---
last_updated: 2026-11-19
---

# 08 Operating guide

## Supported configuration matrix

| Component | Supported configuration | Evidence |
|---|---|---|
| OpenSSL consumer | 3.x or 4.x, provider loaded via OPENSSL_CONF | E-01, E-14 |
| Go runtime | Built with `GOFIPS140=v1.0.0` from the frozen archive | E-08 |
| Runtime mode | `GODEBUG=fips140=on` (build default; gate-enforced) | E-09, E-13 |
| Providers in config | gofips + base only; no default, no legacy | E-05, E-06 |
| TLS version | 1.3, and 1.2 with the extended master secret; records through the module's TLS 1.3 and TLS 1.2 GCM (page 03) | E-37, E-42 |
| TLS ciphers | TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256. TLS 1.2: ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM or AES-256-GCM | E-03, E-17, E-42 |
| Key exchange | P-256, P-384 | E-13 (N7), E-40 |
| Certificates | ECDSA P-256 or P-384; RSA (2048 bits or more) verified, never signed | E-03, E-40 |
| Session tickets | On (the default); resumption verified in both directions | E-20 |

## Required environment and config

- `OPENSSL_CONF` pointing at a gofips-only conf (module path plus
  `activate = 1`; base provider activated).
- `GODEBUG=fips140=on` on every process.
- Applications that need SHA-1 for non-security identifiers get it as a
  labelled non-approved digest (page 03). It works under `fips140=on`
  only; under `fips140=only` Go refuses it.
- Secrets used as HMAC keys must be at least 14 bytes (the 112-bit
  floor); a shorter key is refused.
- GCM callers other than TLS: one data update per message on encrypt, and
  the tag set before the data on decrypt (page 03).

## Deployment checklist

1. Verify the provider `.so` sha256 against `gofips-shipped.txt` in the
   release's evidence bundle (page 10).
2. Verify the module archive digest against SP 11.1 if rebuilding.
3. Install the gofips-only conf; confirm no second OPENSSL_CONF.
4. Start once and confirm the provider loaded and init passed.
5. Confirm MD5 unavailability live (`createHash('md5')` must throw).
6. Confirm `go version -m` shows `GOFIPS140=v1.0.0-c2097c7c`.
7. Record the artifact hashes in the deployment record.
8. On arm64, confirm the bundle holds the arm64 suite run (E-41); the
   claim rests on native evidence there as on amd64.

## Upgrades and patching

- Toolchain and frozen archive are a validated pair per SP 5.3: the build
  toolchain must be the distribution's. Upgrading either means re-verifying
  the digest and rerunning the suite.
- Re-run the negative gates after any provider or config change
  (page 05, E-13).

## Logging and evidence retention

- `GOFIPS_DEBUG=1` traces only on a `-tags gofips_debug` build
  (`debug_tag.go`); release artifacts emit nothing (flag compiled out,
  provider.go). `dispatch.c` emits one env-gated `tls_caps` line.
- Keep with the deployment record: acceptance and gate logs for the
  shipped build, artifact hashes, the SP 5247 PDF (sha256 on page 02).
  The release's evidence bundle (page 10) is the baseline.

## Incident rule: fallback is prohibited

If the provider fails to load, treat it as a boot failure. Do not recover by
removing the conf, unsetting OPENSSL_CONF, adding the default provider, or
turning fips140 off: each changes the crypto in place, and the first two
silently fall back to compiled-in defaults. Recovery: fix the module path
or artifact, or roll back. Boot failure with no fallback is the designed
behavior (page 05).

## Bootstrapping note

Boot happens inside the Node/OpenSSL process start: the config is read at
library init, the provider initializes, its exclusive-FIPS gate runs, and
the module's integrity self-test plus KATs run at Go runtime init. Failure
at any point aborts the process.
