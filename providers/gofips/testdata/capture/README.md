# gofips evidence capture

Captures the gofips evidence logs from the current tree into an output
directory. The release workflow runs it and ships the result, with the
native suite logs from both architectures, as the release's attested
evidence bundle (docs/audit page 10). Nothing is written into the
repository.

```sh
make install-tools          # apko, used to build the node and go-builder images
providers/gofips/testdata/capture/run.sh <out-dir> [work-dir]
```

Needs Docker, python3 and apko on an amd64 host. Native arm64 evidence is
not captured here: CI produces it on arm64 runners (audit E-41). The
suites build and run in containers.

## What runs where

| Script | Container | Produces |
|---|---|---|
| `host.sh` | `gofips-capture:local` (Go 1.26.11, OpenSSL 4.0.3, Docker CLI on the host socket) | host suites, Node integration, interop, benchmark, E-27 reproduction |
| `arm64.sh` | `golang:1.26.11` with Debian's arm64 cross toolchain and OpenSSL, run under `qemu-aarch64` | arm64 functional record (E-04, E-12), paramshape13 ABI 3 |
| `parity.sh` | `gofips-capture:local` with the genuine FIPS provider | official FIPS provider parity (E-36), paramshape13 ABI 1-2 |
| `matrix.sh` | Ubuntu 24.04 (OpenSSL 3.0.13), Debian (3.5.7), `gofips-capture:local` (4.0.3) | OpenSSL version matrix (E-38) |

Inputs fetched and verified on the way: OpenSSL 4.0.3 (release tarball
sha256), the Docker CLI (signed apt repository, key fingerprint pinned),
the OpenSSL 3.5.9 compat pair (`fetch-compat-openssl3.sh`, pinned digests)
and `fips.so` from Rocky Linux 10's `openssl-fips-provider`
(`fetch-fips-provider.sh`, RPM signature checked).

`assemble.py` writes the results only if every capture passed. It adds a
provenance header to each log, masks host paths, and redacts the throwaway
test key and shared secret that debug traces print.

`run-tls-bench.sh` bind-mounts its own directories into containers. Under
nested Docker those paths must exist on the host, so `host.sh` works in a
directory mounted at the same path inside and outside the container.
