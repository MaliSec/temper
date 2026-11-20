# base-shell: troubleshooting shell (busybox)

The smallest image with a working shell, used to debug the other bases.
Troubleshooting only, never a production runtime.

## Package set

| package            | purpose                          | notes |
|--------------------|----------------------------------|-------|
| `wolfi-baselayout` | minimal Wolfi filesystem layout  | pulls `ca-certificates-bundle` transitively |
| `busybox`          | sh + ~500 applets                | apko auto-generates the `/bin/*` applet symlinks |

No package manager. Every package resolves from the Wolfi index for x86_64
and aarch64; `apko.lock.json` records the exact versions.

## Properties

- Runs as nonroot UID 65532.
- Empty OCI entrypoint (`entrypoint: {}`); start the shell explicitly.
- Built for `amd64` + `arm64`.

## Usage

```
docker run --rm -it ghcr.io/malisec/temper/base-shell:<YYYY.MM.DD> /bin/sh
```

Use it as a troubleshooting sidecar in a pod, or with `kubectl debug
--image=...` against a shell-less workload.

Build (from this directory):

```
apko build apko.yaml base-shell:local base-shell.tar --arch amd64,arm64
```

## Role in the family

The other runtime bases (`static`, `base-glibc`) ship
without a shell. Their `:debug` variants are the base plus `busybox` (see
their READMEs), which is what `base-shell` provides on its own.
`base-glibc-dev` already contains busybox, since builders need it.
