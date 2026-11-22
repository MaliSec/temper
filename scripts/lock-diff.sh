#!/usr/bin/env bash
#
# lock-diff.sh: list package changes between the committed apko lockfiles
# and the working tree, as a Markdown table (used for relock PRs).
#
# Usage:
#   ./scripts/lock-diff.sh             # compare against HEAD
#   BASE=<dir> ./scripts/lock-diff.sh  # compare against lockfiles in another tree
set -euo pipefail
[ -z "${BASE:-}" ] || BASE=$(realpath -m "$BASE")
. "$(dirname "$0")/project.sh"
q='[.contents.packages[] | "\(.architecture) \(.name) \(.version)"] | sort | .[]'

old_lock() {
  if [ -n "${BASE:-}" ]; then cat "$BASE/$1" 2>/dev/null || echo '{}'
  else git show "HEAD:./$1" 2>/dev/null || echo '{}'; fi
}

rows=""
for l in images/*/apko*.lock.json; do
  img=$(basename "$(dirname "$l")")
  case "$l" in *.debug.lock.json) img="$img (debug)" ;; esac
  rows+=$(join -a1 -a2 -e '-' -o 0,1.2,2.2 \
      <(old_lock "$l" | jq -r "$q" 2>/dev/null | awk '{print $1"/"$2, $3}' | sort) \
      <(jq -r "$q" "$l" | awk '{print $1"/"$2, $3}' | sort) |
    awk '$2 != $3 { split($1, a, "/"); print a[2], $2, $3, a[1] }' |
    # one row per package and version change; architectures that match are joined
    awk -v img="$img" '{ k = $1 " " $2 " " $3; arch[k] = (k in arch) ? arch[k] ", " $4 : $4; if (!(k in seen)) { seen[k] = 1; order[++n] = k } }
      END { for (i = 1; i <= n; i++) { split(order[i], f, " "); printf "| %s | %s | %s | %s | %s |\n", img, f[1], f[2], f[3], arch[order[i]] } }')
  rows+=$'\n'
done
rows=$(printf '%s' "$rows" | sed '/^$/d')
if [ -z "$rows" ]; then
  echo "No package changes."
  exit 0
fi
echo "| Image | Package | Old | New | Arch |"
echo "|---|---|---|---|---|"
printf '%s\n' "$rows"
