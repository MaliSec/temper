# Python runtime base image (distroless, glibc tier)

The Python runtime on glibc-family Wolfi packages, with CA certificates and
tzdata. No shell, no package manager, no pip executable. Build Python
application images on top of it, for example with `FROM` in a Dockerfile or
a second apko config.

## Runtime line choice

`python-3.14` is the newest stable line with broad package support.
`python-3.13`, which receives security fixes until 2029, is published as
`python:3.13` from `images/python-3.13`. Exact versions are pinned in
`apko.lock.json` and change with each relock.

The interpreter binary is `/usr/bin/python3.14` (`/usr/bin/python3.13` in
`python:3.13`); use an exec-form entrypoint, since there is no shell to
prefix `/bin/sh -c`.

## Package set

- `wolfi-baselayout`: minimal Wolfi filesystem layout. Not `wolfi-base`,
  which pulls in `apk-tools`; runtime images have no package manager.
- `glibc` + `glibc-locale-posix`: glibc runtime. The posix locale provides
  `C.UTF-8` (`LANG=C.UTF-8` is set).
- `libgcc`: glibc-family runtime library.
- `python-3.14`: the runtime. Its dependency closure brings the native
  libraries the stdlib links against (openssl/libcrypto, sqlite, readline,
  ncurses, expat, ffi, bz2, xz, zlib, gdbm, mpdecimal, libuuid, brotli) and
  `py3-pip-wheel`: a single `.whl` file under `/usr/share/python-wheels`
  with no entry points, present only because the Wolfi `python-3.14-base`
  package requires it. There is no `pip` module or executable; the smoke
  check confirms `import pip` raises ImportError.
- `ca-certificates-bundle`: TLS trust anchors. `SSL_CERT_FILE` and
  `SSL_CERT_DIR` are set so `ssl.create_default_context()` and pip's
  eventual consumers pick them up.
- `tzdata`: full timezone database.

`PYTHONDONTWRITEBYTECODE=1` keeps the image read-only-rootfs compatible
(policy §1.3): the interpreter writes no `__pycache__` directories into its
own rootfs at runtime.

## No dev/toolchain variant

There is no `python-dev` variant and no `-debug` variant. The only
compiler/toolchain image is `base-glibc-dev`, for build stages.
Consumers that need build-time headers use a separate `base-glibc-dev`
stage, not this image.

## Entrypoint

Empty (`entrypoint: {}`) because this is a base image. Images built on it
set their own exec-form entrypoint, e.g.
`entrypoint: {command: /usr/bin/python3.14 /app/main.py}`.

## Security posture

- Runs as nonroot UID 65532 by default (policy §1.1).
- No setuid/setgid files (policy §1.2), verified post-build by
  `scripts/check-policy.sh`.
- No `apk`, no busybox, no shell (policy §1.5, §2), verified post-build.
- Packages pinned by the committed `apko.lock.json` (policy §1.6). The build
  runs against the lockfile, and CI reports lockfile drift.

## Build

    ./scripts/build.sh --lock --image python   # only when packages drift
    ./scripts/build.sh --image python
    ./scripts/check-policy.sh python

## Smoke

    docker load < dist/python.tar
    docker run --rm --entrypoint /usr/bin/python3.14 python:local-<arch> --version   # 3.14.x; <arch> is amd64 or arm64

`tests/smoke-python.py` (run by `tests/run.sh` against the loaded image,
variable `PYTHON_IMAGE_REF`) covers interpreter startup, stdlib imports
that exercise the locked native libraries, a TLS handshake with the CA
bundle, the nonroot uid, and the absence of shell/apk/pip.

## Tags

Two lines are published in this repository: 3.14 (the newest stable line, this
directory) and 3.13 (security fixes until 2029, `images/python-3.13`).

- `python:3.14` follows the newest release on the 3.14 line (forward only).
- `python:3.13` follows the newest release on the 3.13 line (forward only).
- `python:3.14-YYYY.MM.DD`, `python:3.13-YYYY.MM.DD` and `python:YYYY.MM.DD`
  (the 3.14 line) never move.
- `python:latest` follows the newest release of the 3.14 line.

Pin a digest for reproducible builds.
