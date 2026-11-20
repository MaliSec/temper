# go-builder: Go build-stage image

A build-stage image for Go service Dockerfiles, in place of an upstream
builder such as `golang:1.26-alpine`, so the build stage runs on Temper too.

## Package set

| package                 | purpose                                    |
|-------------------------|--------------------------------------------|
| `wolfi-baselayout`      | filesystem layout                          |
| `ca-certificates-bundle`| TLS for the module proxy                   |
| `go-1.26`               | the toolchain                              |
| `build-base`            | gcc, binutils, glibc-dev, make, pkgconf (the cgo path) |
| `bash`                  | the shell some build scripts require       |
| `git`                   | VCS module fetch + buildvcs stamping       |
| `wget`                  | HTTP downloader                            |
| `busybox`               | the shell build scripts run under          |

Exact versions are pinned in `apko.lock.json` and change with each relock.

go-1.26 declares no dependencies, so `build-base` and `bash` are listed
explicitly.

## Properties

- Build only, never a production runtime. Like `base-glibc-dev`, it carries
  a shell and toolchain by design. The hardening policy governs runtime
  images, and runtime stages copy only the built binaries out of this one.
- Runs as nonroot UID 65532 (`GOTOOLCHAIN=local` pinned; `HOME=/home/nonroot`).
- Built for `amd64` + `arm64`, and tested natively on both in CI.

## Usage

```dockerfile
# The consuming Dockerfile:
ARG BUILDER=ghcr.io/malisec/temper/go-builder@sha256:<digest>
FROM ${BUILDER} AS build
WORKDIR /src
COPY . .
RUN git config --global --add safe.directory /src \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out ./cmd/…
```

`git config --global --add safe.directory` is required when the source
checkout is bind-mounted from a different uid.

## Verification

- `scripts/check-policy.sh`: nonroot, no setuid, no apk.

## Tags

- `go-builder:1.26` follows the newest release on the 1.26 line (forward only).
- `go-builder:1.26-YYYY.MM.DD` and `go-builder:YYYY.MM.DD` never move.
- `go-builder:latest` follows the newest release. If the image moves to a new
  line, `latest` moves with it and `go-builder:1.26` stops receiving releases.

Pin a digest for reproducible builds.
