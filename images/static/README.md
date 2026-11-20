# static: no-libc distroless base

The smallest base for fully static binaries: `CGO_ENABLED=0` Go,
musl-targeted Rust, or any statically linked executable. Like every Temper
image, it ships with an SBOM, a signature and attestations.

## Package set

| package               | purpose                                | notes |
|-----------------------|----------------------------------------|-------|
| `wolfi-baselayout`    | minimal Wolfi filesystem layout        | pulls `ca-certificates-bundle` transitively |
| `ca-certificates-bundle` | Mozilla root CA bundle               | listed explicitly; provides TLS trust out of the box |

No libc, no shell, no package manager, no busybox. `tzdata` is deliberately
absent (UTC default; app images add it when needed).

Every package resolves from the Wolfi index for x86_64 and aarch64;
`apko.lock.json` records the exact versions.

## Properties

- Runs as nonroot UID 65532 (`accounts.run-as`).
- Empty OCI entrypoint (`entrypoint: {}`), since it is a base. Derived
  images set their own exec-form entrypoint, or pass a command at run time.
- `SSL_CERT_FILE` / `SSL_CERT_DIR` point at the CA bundle.
- Built for `amd64` + `arm64` (apko normalizes `x86_64`/`aarch64` to the same
  platforms).

## Usage

```
docker run --rm -it ghcr.io/malisec/temper/static:<YYYY.MM.DD> /your-static-binary
```

As a base: Dockerfile `FROM`, or a derived apko config that adds packages
and sets an exec-form `entrypoint: {command: /usr/bin/app}`, since there is
no shell to prefix `/bin/sh -c`.

Build (from this directory):

```
apko build apko.yaml static:local static.tar --arch amd64,arm64
```

## Debug variant

The image has no shell. Troubleshoot with ephemeral containers
(`kubectl debug`), or build the `:debug` variant. `apko.debug.yaml` includes
`apko.yaml` and adds `busybox`; apko's `include:` appends to the `packages`
list, and apko creates the
busybox applet symlinks. From the repository root:

```bash
apko build images/static/apko.debug.yaml static-debug:local static-debug.tar --arch amd64,arm64
```

The `static-debug` image is for troubleshooting only, never production.
