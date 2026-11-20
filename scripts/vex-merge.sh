#!/usr/bin/env bash
#
# vex-merge.sh: the release's VEX document: every statement in vex/, as one
# OpenVEX v0.2.0 document. Each statement keeps the timestamp of the file
# it came from. The release attaches it, and the signed manifest records
# its sha256.
#
# Usage: scripts/vex-merge.sh <vex-dir> <release>   (output to stdout)
set -euo pipefail

VEX_DIR="${1:?usage: vex-merge.sh <vex-dir> <release>}"
RELEASE="${2:?usage: vex-merge.sh <vex-dir> <release>}"
[ -d "$VEX_DIR" ] || { echo "vex-merge: no directory $VEX_DIR" >&2; exit 1; }

shopt -s nullglob
files=("$VEX_DIR"/*.json)
jq -n --arg id "https://github.com/MaliSec/temper/releases/tag/${RELEASE}#vex" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  {"@context": "https://openvex.dev/ns/v0.2.0", "@id": $id, author: "MaliSec",
   timestamp: $ts, version: 1,
   statements: [inputs | .timestamp as $t | .statements[] | {timestamp: $t} + .]}' "${files[@]}" </dev/null
