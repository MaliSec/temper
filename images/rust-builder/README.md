# rust-builder: Rust build-stage image

A build-stage image for Rust service Dockerfiles and native Node or Python
modules, in place of an upstream builder such as `rust:1-slim`, so the build
stage runs on Temper too.

## Package set

| package                 | purpose                                    |
|-------------------------|--------------------------------------------|
| `wolfi-baselayout`      | filesystem layout                          |
| `ca-certificates-bundle`| TLS for crates.io and git dependencies     |
| `rust-1.100`            | the toolchain: rustc, cargo, clippy, rustfmt |
| `cargo-auditable`       | records each binary's crates in the binary |
| `build-base`            | gcc, binutils, glibc-dev, make, pkgconf (the linker, and crates with C code) |
| `bash`                  | the shell some build scripts require       |
| `git`                   | git dependencies                           |
| `busybox`               | the shell build scripts run under          |

Exact versions are pinned in `apko.lock.json` and change with each relock.

rust-1.100 declares no C toolchain, so `build-base` is listed explicitly.

## Properties

- Build only, never a production runtime. The runtime stage copies only the
  built binary or module out of this one: a static binary into `static`, a
  binary that needs glibc into `base-glibc`, a native module into `node` or
  `python`.
- Runs as nonroot UID 65532 (`HOME=/home/nonroot`,
  `CARGO_HOME=/home/nonroot/.cargo`, whose `bin` is on `PATH`).
- No `rustup`: the toolchain is the image's, and `rust-toolchain.toml` files
  are ignored.
- Built for `amd64` + `arm64`, and tested natively on both in CI.

## Usage

```dockerfile
# The consuming Dockerfile:
ARG BUILDER=ghcr.io/malisec/temper/rust-builder@sha256:<digest>
FROM ${BUILDER} AS build
WORKDIR /src
COPY --chown=65532:65532 . .
RUN cargo auditable build --release --locked
```

`cargo auditable build` embeds the crate list in the binary, where Syft,
Trivy and Grype read it, so the runtime image's scans and SBOM cover the
binary's crates.

Rust's own cryptography crates (`ring`, `rustls`, `sha2`) are outside the
Go Cryptographic Module: a module built with them and copied into a `-fips`
image does not use gofips.

## Verification

- `scripts/check-policy.sh`: nonroot, no setuid, no apk.
- `tests/smoke-rust-builder.sh`: offline, builds a crate whose build script
  compiles C, runs it, and checks that `cargo auditable` recorded its crates.

## Tags

- `rust-builder:1.100` follows the newest release on the 1.100 line (forward only).
- `rust-builder:1.100-YYYY.MM.DD` and `rust-builder:YYYY.MM.DD` never move.
- `rust-builder:latest` follows the newest release. If the image moves to a
  new line, `latest` moves with it and `rust-builder:1.100` stops receiving
  releases.

Pin a digest for reproducible builds.
