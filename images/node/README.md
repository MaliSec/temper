# Node.js runtime base image (distroless, glibc tier)

The Node.js runtime on glibc-family Wolfi packages, with CA certificates and
tzdata. No shell, no package manager. Build Node application images on top
of it, for example with `FROM` in a Dockerfile or a second apko config.

## Runtime line choice

`nodejs-26` is the active LTS line (LTS since 2026-10, supported through
2029-04). `nodejs-24`, in maintenance LTS until 2028-04, is published as
`node:24` from `images/node-24`, for applications on the 24 line.

Exact versions are pinned in `apko.lock.json` and change with each relock.

## Package set

- `wolfi-baselayout`: minimal Wolfi filesystem layout. Not `wolfi-base`,
  which pulls in `apk-tools`; runtime images have no package manager.
- `nodejs-26`: the runtime, linked against OpenSSL 4 (`libssl.so.4`).
- `openssl-3.6-libssl` + `openssl-3.6-libcrypto`: OpenSSL 3 (`libssl.so.3`),
  for native modules built against it, such as Prisma's query and schema
  engines.
- `glibc` + `glibc-locale-posix`: glibc runtime. The posix locale provides
  `C.UTF-8` (`LANG=C.UTF-8` is set).
- `libgcc` + `libstdc++`: runtime libraries for native addons (many npm
  modules ship prebuilt `.node` addons that need libstdc++).
- `ca-certificates-bundle`: TLS trust anchors.
- `tzdata`: full timezone database.

The entrypoint is empty (`entrypoint: {}`) because this is a base image.
Images built on it set their own exec-form entrypoint, e.g.
`entrypoint: {command: /usr/bin/node …}`; there is no shell to prefix
`/bin/sh -c`.

Runs as nonroot UID 65532 by default (security policy). Override
`accounts.run-as` in derived images if needed.

## Build

    ./scripts/build.sh --image node

## Verify

    docker load < dist/node.tar
    docker run --rm --entrypoint /usr/bin/node node:local-<arch> --version   # 26.x; <arch> is amd64 or arm64

The layers contain only the packages above: no apk, no busybox, no shell.

## Tags

Two lines are published in this repository: 26 (active LTS, this
directory) and 24 (maintenance LTS, `images/node-24`).

- `node:26` follows the newest release on the 26 line (forward only).
- `node:24` follows the newest release on the 24 line (forward only).
- `node:26-YYYY.MM.DD`, `node:24-YYYY.MM.DD` and `node:YYYY.MM.DD`
  (the 26 line) never move.
- `node:latest` follows the newest release of the 26 line.

Pin a digest for reproducible builds.
