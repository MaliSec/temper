#!/usr/bin/env bash
#
# newest-date-tag.sh: print the newest release date tag among the tags read
# on stdin, one per line. Date tags are YYYY.MM.DD, and YYYY.MM.DD.N for a
# further release the same day, which sorts after the plain date. Other
# tags (latest, sha256-..., signatures) are ignored. Prints nothing if
# there is no date tag.
#
# Usage: crane ls <repo> | ./scripts/newest-date-tag.sh
set -euo pipefail
grep -E '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]*)?$' \
  | awk -F. '{ printf "%s %s %s %d %s\n", $1, $2, $3, (NF == 4 ? $4 : 0), $0 }' \
  | sort -k1,1n -k2,2n -k3,3n -k4,4n | tail -1 | cut -d' ' -f5 || true
