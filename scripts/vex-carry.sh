#!/usr/bin/env bash
#
# vex-carry.sh: extend VEX statements that have evidence (vex/evidence/) to
# the package versions the lockfiles now ship, when the source of each new
# version shows the same status. Run after a relock; the relock pull
# request's CI then runs each statement's behavioural check in the built
# images (tests/vex-checks.sh) on both architectures.
#
# For a new version of a package line, Wolfi's recipe for exactly that
# version (wolfi-dev/os history) gives the CPython commit it builds and the
# commits it cherry-picks. The statement is extended when:
#   fixed:        a fix commit in the evidence is an ancestor of that
#                 commit, or is cherry-picked;
#   affected:     no commit in its history mentions the upstream issue, and
#                 the recipe cherry-picks neither the issue nor its fix;
#   not_affected: always (it rests on the code being absent; the check in
#                 CI fails the relock if the image is vulnerable).
# Otherwise the statement is left as it is and the version is reported for
# review: a finding it would cover shows as unreviewed until then.
#
# Prints a Markdown summary. Needs gh (authenticated), git and jq.
#
# Usage: scripts/vex-carry.sh
set -euo pipefail
cd "$(dirname "$0")/.."

REGISTRY_REPO="ghcr.io/malisec/temper"
CPYTHON="https://github.com/python/cpython"
WOLFI="wolfi-dev/os"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git init -q "$work/cpython"
git -C "$work/cpython" remote add origin "$CPYTHON"

carried=() review=()

# repository -> image directories (as vex-check.sh).
declare -A dirs_of
for d in images/*/; do
  n=$(basename "$d"); r=$n
  [ ! -f "$d/repo" ] || r=$(tr -d '[:space:]' < "$d/repo")
  dirs_of[$r]+="$n "
done

# recipe <package> <version-rN>: "<wolfi commit> <cpython commit> <cherry-picked commits...>"
# from the newest wolfi-dev/os commit whose recipe builds exactly that version.
declare -A recipe_cache
recipe() {
  local pkg=$1 full=$2 key="$1@$2"
  if [ -z "${recipe_cache[$key]+x}" ]; then
    local ver=${full%-r*} epoch=${full##*-r} found="" sha y v e commits
    for sha in $(gh api "repos/$WOLFI/commits?path=$pkg.yaml&per_page=100" --jq '.[].sha'); do
      y=$(gh api "repos/$WOLFI/contents/$pkg.yaml?ref=$sha" -H 'Accept: application/vnd.github.raw')
      v=$(sed -nE 's/^  version: "?([^" #]+)"?.*$/\1/p' <<<"$y" | head -1)
      e=$(sed -nE 's/^  epoch: ([0-9]+).*$/\1/p' <<<"$y" | head -1)
      [ "$v" = "$ver" ] && [ "$e" = "$epoch" ] || continue
      commits=$(grep -E "^ +expected-commit: [0-9a-f]{40}$" <<<"$y" | awk '{print $2}')
      [ "$(wc -w <<<"$commits")" = 1 ] || { found="error: $pkg $full: the recipe has $(wc -w <<<"$commits") expected commits"; break; }
      grep -q "repository: $CPYTHON\$" <<<"$y" || { found="error: $pkg $full: the recipe does not build $CPYTHON"; break; }
      found="$sha $commits $(sed -nE 's#^ +[^ /]+/([0-9a-f]{40}): .*$#\1#p' <<<"$y" | tr '\n' ' ')"
      break
    done
    recipe_cache[$key]=${found:-"error: $pkg $full: no recipe in the last 100 commits of $WOLFI builds it"}
  fi
  printf '%s\n' "${recipe_cache[$key]}"
}

declare -A fetched
fetch() {
  [ -n "${fetched[$1]:-}" ] && return
  git -C "$work/cpython" fetch -q --filter=blob:none origin "$1"
  fetched[$1]=1
}
ancestor() { # ancestor <commit> <of>: false if <commit> is not in the fetched history
  git -C "$work/cpython" cat-file -e "$1^{commit}" 2>/dev/null \
    && git -C "$work/cpython" merge-base --is-ancestor "$1" "$2"
}

shopt -s nullglob
for ev in vex/evidence/*.json; do
  cve=$(jq -r .vulnerability "$ev")
  doc="vex/$cve.json"
  issue=$(jq -r .issue "$ev")
  mapfile -t upstream < <(jq -r '.upstream[]' "$ev")
  changed=false
  while IFS=$'\t' read -r pkg status fixes; do
    read -ra fix <<<"$fixes"
    # Each (repository, version) the lockfiles ship that no statement covers.
    while IFS=$'\t' read -r repo ver; do
      sub="pkg:apk/wolfi/$pkg@$ver"
      product="pkg:oci/$repo?repository_url=$REGISTRY_REPO/$repo"
      jq -e --arg p "$product" --arg s "$sub" \
        'any(.statements[].products[]; ."@id" == $p and any(.subcomponents[]; ."@id" == $s))' "$doc" >/dev/null && continue
      # The statement with this status that names this repository and package.
      idx=$(jq --arg p "$product" --arg pk "pkg:apk/wolfi/$pkg@" --arg st "$status" \
        '[.statements | to_entries[] | select(.value.status == $st and any(.value.products[];
          ."@id" == $p and any(.subcomponents[]; ."@id" | startswith($pk)))) | .key][0] // empty' "$doc")
      [ -n "$idx" ] || { review+=("$cve $repo: $pkg $ver not carried: no $status statement names $repo and $pkg"); continue; }
      r=$(recipe "$pkg" "$ver")
      if [[ "$r" == error:* ]]; then review+=("$cve $pkg $ver: ${r#error: }"); continue; fi
      read -r wolfi src picks <<<"$r"
      read -ra picked <<<"${picks:-}"
      fetch "$src"
      ok=false reason=""
      case "$status" in
        fixed)
          for f in "${fix[@]}"; do
            if ancestor "$f" "$src" || printf '%s\n' "${picked[@]}" | grep -qx "$f"; then ok=true; fi
          done
          $ok || reason="Wolfi's recipe (wolfi-dev/os ${wolfi:0:8}) builds CPython ${src:0:8}, which has no recorded fix commit, and cherry-picks none"
          ;;
        affected)
          hit=$(git -C "$work/cpython" log --format=%h -E --grep="${issue}([^0-9]|$)" "$src" | head -3 | tr '\n' ' ')
          for f in "${upstream[@]}"; do printf '%s\n' "${picked[@]}" | grep -qx "$f" && hit+="cherry-pick ${f:0:8} "; done
          if [ -z "$hit" ]; then ok=true
          else reason="CPython ${src:0:8} (wolfi-dev/os ${wolfi:0:8}) has commits for $issue: ${hit% }; the fix may have arrived"; fi
          ;;
        not_affected) ok=true ;;
      esac
      if $ok; then
        jq --argjson i "$idx" --arg p "$product" --arg s "$sub" \
          '(.statements[$i].products[] | select(."@id" == $p) | .subcomponents) += [{"@id": $s}]' "$doc" > "$work/doc.json"
        mv "$work/doc.json" "$doc"
        changed=true
        carried+=("$cve $repo: $pkg $ver ($status; CPython ${src:0:8})")
      else
        review+=("$cve $repo: $pkg $ver not carried ($status): $reason")
      fi
    done < <(for repo in "${!dirs_of[@]}"; do
      for d in ${dirs_of[$repo]}; do
        jq -r --arg n "$pkg" --arg r "$repo" '.contents.packages[] | select(.name == $n) | [$r, .version] | @tsv' "images/$d/apko.lock.json"
      done
    done | sort -u)
  done < <(jq -r '.lines | to_entries[] | [.key, .value.status, ((.value.fix // []) | join(" "))] | @tsv' "$ev")
  if $changed; then
    jq --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.version += 1 | .timestamp = $ts' "$doc" > "$work/doc.json"
    mv "$work/doc.json" "$doc"
  fi
done

echo "### VEX statements"
echo
if [ "${#carried[@]}" = 0 ] && [ "${#review[@]}" = 0 ]; then
  echo "Every statement with evidence covers the versions this relock ships."
fi
if [ "${#carried[@]}" -gt 0 ]; then
  echo "Extended to the new versions (the behavioural checks run in this PR's CI):"
  echo
  printf -- '- %s\n' "${carried[@]}"
  echo
fi
if [ "${#review[@]}" -gt 0 ]; then
  echo "**Needs review** (not extended; the findings show as unreviewed until then):"
  echo
  printf -- '- %s\n' "${review[@]}"
fi
