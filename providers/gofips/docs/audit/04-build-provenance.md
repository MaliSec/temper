---
last_updated: 2026-11-19
---

# 04 Build and provenance

## Reproducible build (amd64, native)

Environment: Go 1.26.11 linux/amd64 with the toolchain's embedded
validated archive at `$GOROOT/lib/fips140/v1.0.0-c2097c7c.zip`. CI checks
the archive's digest on each run (E-08).

```sh
# verify the frozen module archive against SP 5247 section 11.1
sha256sum "$(go env GOROOT)/lib/fips140/v1.0.0-c2097c7c.zip"
# expect daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b

(cd providers/gofips && GOFIPS140=v1.0.0 go build -ldflags=-checklinkname=0 -buildmode=c-shared -o gofips.so .)

# verify the approved-mode marker (SP 11.1)
go version -m providers/gofips/gofips.so | grep GOFIPS140
# expect: build GOFIPS140=v1.0.0-c2097c7c
```

Non-FIPS build (control): the same command without `GOFIPS140`.
The acceptance harness refuses it when `GOFIPS_REQUIRE_FIPS=1` is set
(E-01).

## Artifact digests

Each release's evidence bundle records the digests of the binaries its
logs came from: `artifact-digests.txt` for the capture, and
`gofips-shipped.txt` for the shipped `gofips.so` the native suites ran
against (E-21, E-43). A digest identifies one build; a rebuild with a
different toolchain or environment differs.

## ELF facts

- The provider object has zero libcrypto-namespaced undefined symbols
  (`nm -D --undefined-only`); its only `DT_NEEDED` is `libc.so.6` (E-23).
  No libcrypto link, so one object serves OpenSSL 3.x and 4.x.
- Verified loads: OpenSSL 3.0.13, 3.5.7, 3.6.5 and 4.0.3 (E-38), the
  Temper node image's OpenSSL 4.0.3 (libcrypto.so.4, E-14), the compat
  pair's OpenSSL 3.5.9 (libcrypto.so.3, E-01), and OpenSSL 3.6.5 and 4.0.3
  in one process sharing one `gofips.so` (E-44).

## Compat pair provenance and hashes

The compat pair is the OpenSSL 3.5 ABI test target for the C suites:
OpenSSL 3.5.9, built against glibc 2.34, so it links on any glibc 2.34+
host. It is not committed. `testdata/fetch-compat-openssl3.sh <output-dir>`
extracts it for the host's architecture from

    registry.access.redhat.com/ubi9/ubi-minimal@sha256:baafce2d34783a28b4a472779f304e97e00f9d35c99553bc53b068b14344d9a9

and checks these hashes; set `GOFIPS_LIBCRYPTO_DIR` to the output
directory.

| File | SHA256 | Note |
|---|---|---|
| libcrypto.so.3 | 0a19a8d0252b09c68ba1a4e8a1398248f636da837e5074529861f7b92a451280 | x86-64, OpenSSL 3.5.9 |
| libssl.so.3 | ce08056805f0ed2ce702254609f138f43e1819a4327c00afaec754d46e001605 | x86-64, OpenSSL 3.5.9 |
| libcrypto.so.3 | 09a28b8d2f7a70b462ec1a7b2ca53956c74d834879c6e62ddb1a159c54ba7f18 | arm64, OpenSSL 3.5.9 |
| libssl.so.3 | b9398eca5e54975a3dbc926657cb6e0fda6d70777ed777d7e72f0d75a9bc507a | arm64, OpenSSL 3.5.9 |

The arm64 qemu evidence (E-12) uses Debian's arm64 OpenSSL 3.5.7
(libssl3t64:arm64 3.5.7-1~deb13u3):

| File | SHA256 |
|---|---|
| libcrypto.so.3 (aarch64) | 809909371a1db7d2b9cac4c2fa2eff63eb6169d5979416d94155955a7ad32516 |
| libssl.so.3 (aarch64) | b3b9a479537bded757b818bb787413d8f8f636135e6546c84e90688eca1dc842 |

## Ownership and licensing

- Adapter code: Temper repository, Apache-2.0 (repo LICENSE).
- Go Cryptographic Module: BSD-style license per SP 5.3 (E-16).
- OpenSSL 3.5.9 pair: Apache-2.0 (OpenSSL upstream), built by Red Hat;
  consumed unmodified, hashes pinned above.
- Compat pair maintenance: the pair is a test target only; any image
  shipping an OpenSSL 3 library owns its patch lifecycle.

## arm64 builds

The shipped arm64 provider is built natively: the melange recipe
(`packages/gofips/melange.yaml`) runs on GitHub's arm64 runners with
Wolfi's arm64 Go toolchain and OpenSSL headers, and applies the same two
checks as on amd64 (the module archive digest and the `GOFIPS140` marker).
The arm64 CI suites (E-41) build and test the provider natively from the
same source.

The capture's `arm64-evidence.txt` (E-12, in the evidence bundle) records
the qemu cross-build: Debian's arm64 OpenSSL headers, run under emulation.
