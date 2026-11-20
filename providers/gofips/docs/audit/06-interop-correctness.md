---
last_updated: 2026-11-19
---

# 06 Interoperability and correctness

## Legacy-constructor routing (E-35)

`EVP_PKEY_CTX_new(pk, NULL)` resolves the exchange/signature with a
NULL property query; which implementation serves it is a core decision:

- Exclusive config (gofips-only OPENSSL_CONF; the supported shape):
  legacy-ctor ECDH/ECDSA dispatch through gofips (asserted by
  `legacy_ctor_boundary.c` configured mode, provider dispatch
  counters). A default-served derive here is a routing regression.
- Default reachable: outside the supported configuration. The core
  serves the fetch from the default provider (implicit default;
  `OSSL_PROVIDER_load` alone does not prevent it) with the exported
  scalar, measured identical for the genuine OpenSSL FIPS provider
  (fips.so 3.5.9); core behavior not interceptable without API
  interposition (out of scope, page 05). Gofips claims no dispatch it
  did not perform (counters asserted 0). Parity evidence:
  E-36 (release bundle).

This is shared core behavior, not a gofips divergence; the exclusive config
(page 08) keeps every fetch inside gofips. The control mode pins both
contracts against regression.

## Node TLS gates (Temper node image)

In-image suite (E-14, "NODE INTEGRATION: ALL STAGES PASSED", runner exit
0): real
`tls.createServer` / `tls.connect` handshakes under the gofips-only
config negotiate TLSv1.3 with TLS_AES_256_GCM_SHA384, carry
application data both ways, and complete 5 serial and 20 parallel
handshakes; alongside negative gates N5 to N8 of page 05 (against a
baseline that connects), environment negatives N9 to N11, the poison
routing control, and the positive default-provider control.

C-level TLS (E-37, `tls13_handshake.c`): gofips client to default
server, default client to gofips server, and gofips on both ends, for
both GCM suites; each case exchanges 600 records of 1 to 16384 bytes
and survives a KeyUpdate; all pass under `GODEBUG=fips140=on` and
`fips140=only`.

## Both-direction OpenSSL peer tests

`run-interop-regression.sh` (E-19): both directions complete a TLS 1.3
connection (ECDSA P-256 cert, prime256v1, session tickets on):
- A: gofips client to default-provider OpenSSL server. PASS.
- B: default-provider client to gofips Node server. PASS.
- fips140=off refused on the interop config: PASS (rc=139).

## RFC 8446 KAT

The TLS 1.3 key schedule treats an absent input keying material (IKM) as
zeros of hash length (RFC 8446 HKDF-Extract(0,0)), with and without a
salt. The early secret matches the RFC 8446 value; the run prints it in
`interop-regression.log` (E-19), and the C suite checks the KDF vectors.

## X509 digest probe

`x509_digest_probe.c` (E-28): X509_digest(SHA256) under the gofips-only
conf on both ABIs. The digest matches the pinned DER hash on both, 8
Go-dispatch lines per ABI prove routing, MD5 is unfetchable (E-28).

## OpenSSL 3 and 4 in one process

The node images ship OpenSSL 3.6.5 beside 4.0.3: Node links
libcrypto.so.4, and native modules built for OpenSSL 3 (Prisma's engines)
link libcrypto.so.3. Both read the same config and load the same
`gofips.so`. `dual_openssl.c` (E-44) loads both libraries in one process,
each with the config the images ship, and checks that each has gofips,
cannot use MD5, gets every digest it serves from gofips, loads PEM keys,
and stays correct with 4 threads per library interleaved.

## Base provider digests

Wolfi's OpenSSL 3.6 build patches its base provider to also serve SHA-1
and MD5 (`provider=base`); upstream's base, and Wolfi's OpenSSL 4, serve
no digests. With base active, as the config needs it for its encoders and
decoders, those names would resolve to base, outside the module. Two
measures keep them in gofips:

- The config prefers gofips: `default_properties = ?provider=gofips`. An
  optional preference, so a name only base serves (its encoders, decoders
  and store loaders) still resolves there; SHA-1 resolves to gofips's.
- On an OpenSSL 3 core (read from the core's version at provider init),
  gofips also registers MD5 as a refused row: a fetch resolves to it and
  every entry point fails. On OpenSSL 4 the row is not registered.

`config_pref.c` (E-45) checks both on OpenSSL 3.0.13, 3.5.7, 3.6.5 and
4.0.3 with the config the images ship. An application that names another
provider in its own property query (`provider=base`) chooses it; that is
outside the claim, like loading another provider.

## CI status

The `gofips-provider-suites` job (E-29), on amd64 and arm64, runs:

- the FIPS module integrity check (SP 11.1);
- the C acceptance suite;
- the Node integration and fail-closed runner;
- the cross-provider interop regressions and the RFC 8446 KAT;
- the X509 digest probe on both ABIs;
- OpenSSL 3 and 4 in one process (E-44);
- the differential suite (T1 to T13), regtest and guardtest;
- SHA-3, PBKDF2 and streaming ECDSA; RSA verification, P-384 and
  certificate chains; TLS 1.2; the GCM nonce lifecycle and caller
  contract; the TLS 1.3 GCM unit tests and handshakes; each in
  `fips140=on` and `only`;
- the build/mode matrix and release-binary scan;
- the EC boundary corpus;
- the legacy-ctor routing gate (E-35);
- the parameter-handling regressions;
- the panic-containment coverage;
- the documented-command gate;
- the in-image TLS benchmark.

Logs upload as artifacts.
