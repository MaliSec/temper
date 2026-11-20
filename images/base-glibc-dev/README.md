# base-glibc-dev: build stage for the glibc tier

Compiler toolchain and headers for builder stages, multi-stage images and
melange package builds. Not a production runtime image: production images
stay distroless (no shell), and this image exists to build them.

## Package set

| package               | purpose                                        | notes |
|-----------------------|------------------------------------------------|-------|
| `wolfi-baselayout`    | minimal Wolfi filesystem layout                | pulls `ca-certificates-bundle` transitively |
| `glibc-dev`           | glibc headers + dev symlinks                   | pulls `libxcrypt-dev` and `linux-headers` transitively |
| `gcc`                 | GNU C/C++ compiler driver                      | provides `gcc`, `g++`, `c++`, `cpp`; pulls `binutils`, `libstdc++-dev`, `libquadmath`, `openssf-compiler-options`, `posix-cc-wrappers` transitively |
| `make`                | build automation                               | |
| `linux-headers`       | kernel UAPI headers (listed explicitly)        | already pulled by `glibc-dev` |
| `pkgconf`             | pkg-config compatible .pc resolver             | |
| `busybox`             | shell for configure/make scripts in builders   | the one deliberate shell: a builder must run `/bin/sh` |

Every package resolves from the Wolfi index for x86_64 and aarch64;
`apko.lock.json` records the exact versions. No dependency pulls in a
package manager (`apk-tools`).

## Properties

- Runs as nonroot UID 65532 (override in derived configs if a builder
  needs root).
- Empty OCI entrypoint (`entrypoint: {}`).
- Built for `amd64` + `arm64`.

## Usage

As a `FROM` builder stage, or as the base for compiling in apko/melange
package builds:

```
docker run --rm -v "$PWD":/work -w /work ghcr.io/malisec/temper/base-glibc-dev:<YYYY.MM.DD> \
  sh -c 'gcc -O2 -o app app.c && ./app'
```

Build (from this directory):

```
apko build apko.yaml base-glibc-dev:local base-glibc-dev.tar --arch amd64,arm64
```

## Debug variant

`busybox` is already in the image, so the `:debug` variant
(`apko.debug.yaml`) has the same package set. The image is its own debugging
base.
