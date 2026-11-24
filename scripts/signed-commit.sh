#!/usr/bin/env bash
# Commits the working-tree changes under the given paths (relative to the
# repository root) as one commit on HEAD, through GitHub's Git API, and points
# <branch> at it (created if missing, otherwise force-updated). With an App
# token and no author or committer given, GitHub signs the commit as the App,
# so it passes a ruleset that requires signed commits.
#
# Usage: signed-commit.sh <owner/repo> <branch> <message> <path>...
# Needs GH_TOKEN. Prints the new commit's SHA.
set -euo pipefail

[ $# -ge 4 ] || { echo "usage: $0 <owner/repo> <branch> <message> <path>..." >&2; exit 2; }
repo=$1 branch=$2 message=$3
shift 3
cd "$(git rev-parse --show-toplevel)"

base=$(git rev-parse HEAD)
work=$(mktemp -d)
: > "$work/tree.jsonl"
git status --porcelain=v1 -z --untracked-files=all --no-renames -- "$@" |
  while IFS= read -r -d '' entry; do
    path=${entry:3}
    if [ -L "$path" ] || [ -e "$path" ]; then
      if [ -L "$path" ]; then
        mode=120000
        printf '%s' "$(readlink -- "$path")" | base64 -w0 > "$work/content"
      else
        mode=100644
        [ -x "$path" ] && mode=100755
        base64 -w0 -- "$path" > "$work/content"
      fi
      sha=$(jq -n --rawfile c "$work/content" '{content: $c, encoding: "base64"}' |
        gh api "repos/$repo/git/blobs" --input - --jq .sha)
      jq -nc --arg path "$path" --arg mode "$mode" --arg sha "$sha" \
        '{path: $path, mode: $mode, type: "blob", sha: $sha}' >> "$work/tree.jsonl"
    else
      jq -nc --arg path "$path" '{path: $path, mode: "100644", type: "blob", sha: null}' >> "$work/tree.jsonl"
    fi
  done
[ -s "$work/tree.jsonl" ] || { echo "no changes under: $*" >&2; exit 1; }

tree=$(jq -n --arg base_tree "$(git rev-parse "HEAD^{tree}")" --slurpfile tree "$work/tree.jsonl" \
  '{base_tree: $base_tree, tree: $tree}' | gh api "repos/$repo/git/trees" --input - --jq .sha)
commit=$(jq -n --arg message "$message" --arg tree "$tree" --arg parent "$base" \
  '{message: $message, tree: $tree, parents: [$parent]}' | gh api "repos/$repo/git/commits" --input - --jq .sha)

if gh api "repos/$repo/git/ref/heads/$branch" >/dev/null 2>&1; then
  gh api -X PATCH "repos/$repo/git/refs/heads/$branch" -f sha="$commit" -F force=true >/dev/null
else
  gh api "repos/$repo/git/refs" -f ref="refs/heads/$branch" -f sha="$commit" >/dev/null
fi
echo "$commit"
