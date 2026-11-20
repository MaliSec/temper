# node-builder: Node/npm build-stage image

A build-stage image for Node application Dockerfiles, in place of an
upstream builder such as `node:26-alpine`. The Temper `node` runtime image
ships nodejs only (distroless by design); npm lives here.

## Package set

| package                 | purpose                              |
|-------------------------|--------------------------------------|
| `wolfi-baselayout`      | filesystem layout                    |
| `ca-certificates-bundle`| TLS for the registry                 |
| `nodejs-26`             | the toolchain (`nodejs-24` in `node-builder:24`) |
| `npm`                   | the package manager (resolves to `npm-12`; pulls node-gyp) |
| `busybox`               | the shell build scripts run under    |

Exact versions are pinned in `apko.lock.json` and change with each relock.

## Properties

- Build only, never a production runtime. The runtime stage copies only the
  build output and production `node_modules`.
- Runs as nonroot UID 65532 (`HOME=/home/nonroot`).
- The runtime is the Temper `node` image on the same line: build with
  `node-builder:26` for `node:26`, `node-builder:24` for `node:24`.
- Built for `amd64` + `arm64`, and tested natively on both in CI.

## Usage

```dockerfile
# The consuming Dockerfile:
ARG BUILDER=ghcr.io/malisec/temper/node-builder@sha256:<digest>
FROM ${BUILDER} AS build
WORKDIR /src/app
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build && npm ci --omit=dev
```

## Verification

- `scripts/check-policy.sh`: nonroot, no setuid, no apk.

## Tags

Two lines are published in this repository: 26 (active LTS, this
directory) and 24 (maintenance LTS, `images/node-builder-24`).

- `node-builder:26` follows the newest release on the 26 line (forward only).
- `node-builder:24` follows the newest release on the 24 line (forward only).
- `node-builder:26-YYYY.MM.DD`, `node-builder:24-YYYY.MM.DD` and
  `node-builder:YYYY.MM.DD` (the 26 line) never move.
- `node-builder:latest` follows the newest release of the 26 line.

Pin a digest for reproducible builds.
