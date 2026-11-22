#!/usr/bin/env bash
#
# toolbox.sh: run the Temper toolchain from a container image
# (Dockerfile.toolbox) with the same pinned versions CI uses.
#
# Usage:
#   ./scripts/toolbox.sh --build              # build the toolbox image
#   ./scripts/toolbox.sh apko version
#   ./scripts/toolbox.sh melange build ...    # any tool + args
#
# The current directory is mounted at the same absolute path and runs as your
# uid/gid, so outputs land in the repo as with a host install. Tool caches go
# to ./.toolbox-cache/ (git-ignored). TEMPER_PROJECT_DIR, when set, is
# mounted and passed the same way.
set -euo pipefail

TOOLBOX_IMAGE="${TOOLBOX_IMAGE:-temper-toolbox:local}"

if [ "${1:-}" = "--build" ]; then
  shift
  docker build -f Dockerfile.toolbox -t "$TOOLBOX_IMAGE" .
  [ "$#" -eq 0 ] && exit 0
fi

if ! docker image inspect "$TOOLBOX_IMAGE" >/dev/null 2>&1; then
  echo "toolbox image missing — building it (or run: ./scripts/toolbox.sh --build)" >&2
  docker build -f Dockerfile.toolbox -t "$TOOLBOX_IMAGE" .
fi

mkdir -p "$PWD/.toolbox-cache"

USER_ARGS=(-u "$(id -u):$(id -g)")
ENV_ARGS=()
if [ "${SUDO:-0}" = "1" ]; then
  # melange's docker runner leaves root-owned workspace files a nonroot user
  # cannot read. Run as root; build.sh chowns outputs back to HOST_UID/HOST_GID.
  USER_ARGS=(--user 0:0)
  ENV_ARGS=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")
fi

# The repo keeps its host path because melange's docker runner passes mount
# sources to the host daemon, which resolves them on the host. The socket is
# mounted for that runner (bubblewrap cannot run unprivileged in Docker), with
# its group added so the nonroot uid can use it.
DOCKER_ARGS=()
if [ -S /var/run/docker.sock ]; then
  DOCKER_ARGS=(
    -v /var/run/docker.sock:/var/run/docker.sock
    --group-add "$(stat -c %g /var/run/docker.sock)"
    -e DOCKER_HOST=unix:///var/run/docker.sock
  )
fi

PROJECT_ARGS=()
if [ -n "${TEMPER_PROJECT_DIR:-}" ]; then
  p=$(realpath "$TEMPER_PROJECT_DIR")
  PROJECT_ARGS=(-e TEMPER_PROJECT_DIR="$p")
  [ "$p" = "$PWD" ] || PROJECT_ARGS+=(-v "$p":"$p")
fi

exec docker run --rm \
  "${USER_ARGS[@]}" \
  -v "$PWD":"$PWD" \
  -v "$PWD/.toolbox-cache":/cache \
  -e HOME=/cache \
  -e XDG_CACHE_HOME=/cache \
  "${ENV_ARGS[@]}" \
  "${DOCKER_ARGS[@]}" \
  "${PROJECT_ARGS[@]}" \
  -w "$PWD" \
  "$TOOLBOX_IMAGE" "$@"
