#!/usr/bin/env bash
#
# keygen.sh: generate the melange package signing keypair.
#
# Writes melange.rsa and melange.rsa.pub to the repository root, where the
# apko configs expect ./melange.rsa.pub. melange.rsa is git-ignored; never
# commit it.
#
# Usage:
#   ./scripts/keygen.sh          # skip if melange.rsa already exists
#   FORCE=1 ./scripts/keygen.sh  # regenerate even if present
set -euo pipefail
. "$(dirname "$0")/project.sh"

command -v melange >/dev/null 2>&1 || {
  echo "melange not found on PATH — run: make install-tools" >&2
  exit 1
}

if [ -f melange.rsa ] && [ "${FORCE:-0}" != "1" ]; then
  echo "melange.rsa already exists — use FORCE=1 to regenerate (this will"
  echo "invalidate the old key; local lockfile checksums will drift)."
  exit 0
fi

melange keygen

echo "---"
echo "wrote melange.rsa / melange.rsa.pub (repo root)."
echo "Never commit melange.rsa — CI generates its own key per run."
