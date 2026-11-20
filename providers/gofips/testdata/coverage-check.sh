#!/usr/bin/env bash
# coverage-check.sh: assert panictest.c exercises every inventory
# family (mapped to the suite's coarse sections).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
INV="$HERE/panictest-inventory.txt"

inv_fams=$(grep -E "^[a-z0-9-]+: [0-9]+ exports" "$INV" | cut -d: -f1 | sort -u)
test_fams=$(grep -oE -- "---- [a-z0-9-]+ family" "$HERE/panictest.c" | awk "{print \$2}" | sort -u)

map_inv() {
  case "$1" in
    digest-*) echo digest;;
    cipher-*) echo cipher;;
    mac|kdf|tls13kdf|keymgmt|keyexch|sig|rand|provider) echo "$1";;
    *) echo "$1";;
  esac
}

mapped=$(for f in $inv_fams; do map_inv "$f"; done | sort -u)
missing=$(comm -23 <(echo "$mapped") <(echo "$test_fams"))
if [ -z "$missing" ]; then
  echo "COVERAGE: every inventory family is exercised by panictest.c"
  echo "  inventory families: $(echo $inv_fams | tr "\n" " ")"
  exit 0
else
  echo "COVERAGE GAP: inventory families (mapped) NOT exercised:"
  echo "$missing"
  exit 1
fi
