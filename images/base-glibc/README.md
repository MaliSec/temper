# base-glibc: dynamic glibc runtime base

A distroless base for dynamically linked glibc workloads (C/C++ runtimes).

## Package set

| package            | purpose                          | notes |
|--------------------|----------------------------------|-------|
| `wolfi-baselayout` | minimal Wolfi filesystem layout  | pulls `ca-certificates-bundle` transitively |
| `glibc`            | the GNU C library runtime        | all `so:` deps satisfied by glibc itself; no other runtime packages |

No shell, no package manager, no busybox. `tzdata` is deliberately absent
(UTC default). The CA bundle arrives transitively via `wolfi-baselayout`, so
`SSL_CERT_FILE`/`SSL_CERT_DIR` are valid. Images that want a declared CA
dependency add `ca-certificates-bundle`.

Every package resolves from the Wolfi index for x86_64 and aarch64;
`apko.lock.json` records the exact versions.

## Properties

- Runs as nonroot UID 65532.
- Empty OCI entrypoint (`entrypoint: {}`), since it is a base.
- Built for `amd64` + `arm64`.

## Usage

```
docker run --rm -it ghcr.io/malisec/temper/base-glibc:<YYYY.MM.DD> /path/to/dynamic-binary
```

As a base: `FROM`, or a derived apko config that adds runtime packages (for example base-glibc + `ca-certificates-bundle` + `tzdata` for a C++
server).

Build (from this directory):

```
apko build apko.yaml base-glibc:local base-glibc.tar --arch amd64,arm64
```

## Debug variant

The runtime image has no shell. Troubleshoot with ephemeral containers, or
build the `:debug` variant. `apko.debug.yaml` includes `apko.yaml` and adds
`busybox` (apko's `include:` appends to `packages`). From the repository
root:

```bash
apko build images/base-glibc/apko.debug.yaml base-glibc-debug:local base-glibc-debug.tar --arch amd64,arm64
```

The `base-glibc-debug` image is for troubleshooting only, never production.
