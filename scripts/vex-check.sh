#!/usr/bin/env bash
#
# vex-check.sh: check the OpenVEX statements in vex/. Each file holds the
# statements for one vulnerability, named after it (vex/CVE-2026-1234.json).
#
# Fails on a malformed statement: not OpenVEX v0.2.0, an unknown status, a
# not_affected without a justification and impact statement, an affected
# without an action statement, a fixed or under_investigation without
# notes giving the evidence, a
# product that is not a Temper image repository or names no package
# version, or two statements for one product and package version.
#
# Also fails on evidence (vex/evidence/<CVE>.json, read by vex-carry.sh and
# tests/vex-checks.sh) that does not match its statements: a line whose
# status differs from the statements for that package, a fixed line without
# fix commits, a commit that is not a full SHA, or a missing check script.
#
# Reports, without failing, a statement whose package version no image of
# that repository ships any more. Keep it: it still covers the releases
# that shipped that version. The version a relock moves to needs its own.
#
# Usage: scripts/vex-check.sh [vex-dir] [images-dir]
set -euo pipefail

VEX_DIR="${1:-vex}"
IMAGES_DIR="${2:-images}"
REGISTRY_REPO="ghcr.io/malisec/temper"
fails=0 stale=0
fail() { echo "vex: $*" >&2; fails=$((fails + 1)); }

# repository -> the image directories that publish to it (node: node node-24).
declare -A dirs_of
for d in "$IMAGES_DIR"/*/; do
  n=$(basename "$d")
  r=$n; [ ! -f "$d/repo" ] || r=$(tr -d '[:space:]' < "$d/repo")
  dirs_of[$r]+="$n "
done

[ -d "$VEX_DIR" ] || { echo "vex: no directory $VEX_DIR" >&2; exit 1; }
shopt -s nullglob
files=("$VEX_DIR"/*.json)
shopt -u nullglob
for f in "${files[@]}"; do
  vuln=$(basename "$f" .json)
  jq -e . "$f" >/dev/null 2>&1 || { fail "$f: not valid JSON"; continue; }
  jq -e '(.statements | type) == "array" and all(.statements[]; type == "object"
          and ((.products // []) | type) == "array" and all((.products // [])[]; type == "object"
          and ((.subcomponents // []) | type) == "array"))' "$f" >/dev/null 2>&1 \
    || { fail "$f: statements, products and subcomponents must be arrays of objects"; continue; }
  problems=$(jq -r --arg v "$vuln" '
    def enum($xs): . as $x | $xs | index([$x]) != null;
    [ (if ."@context" != "https://openvex.dev/ns/v0.2.0" then "@context is not OpenVEX v0.2.0" else empty end),
      (if (."@id" // "" | startswith("https://")) | not then "@id is not an https URL" else empty end),
      (if (.author // "") == "" then "no author" else empty end),
      (if (.timestamp // "" | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}(\\.[0-9]+)?Z$")) | not then "timestamp is not RFC 3339 UTC" else empty end),
      (if (.version | type) != "number" or .version < 1 then "version is not a positive number" else empty end),
      (if (.statements | type) != "array" or (.statements | length) == 0 then "no statements" else empty end),
      (.statements[]? | . as $s |
        (if $s.vulnerability.name != $v then "a statement names \($s.vulnerability.name), not \($v)" else empty end),
        (if ($s.status | enum(["not_affected", "affected", "fixed", "under_investigation"])) | not then "unknown status \($s.status)" else empty end),
        (if $s.status == "not_affected" and (($s.justification // "") | enum(["component_not_present",
            "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
            "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"]) | not)
          then "not_affected without a valid justification" else empty end),
        (if $s.status == "not_affected" and ($s.impact_statement // "") == "" then "not_affected without an impact statement" else empty end),
        (if $s.status == "affected" and ($s.action_statement // "") == "" then "affected without an action statement" else empty end),
        (if ($s.status == "under_investigation" or $s.status == "fixed") and ($s.status_notes // "") == ""
          then "\($s.status) without status notes" else empty end),
        (if ($s.products | type) != "array" or ($s.products | length) == 0 then "a statement has no products" else empty end)),
      ([.statements[]?.products[]? | ."@id" as $p | (.subcomponents // [])[]? | "\($p) \(."@id")"]
        | group_by(.) | map(select(length > 1) | .[0])[] | "two statements for \(.)")
    ] | .[]' "$f")
  while IFS= read -r p; do [ -z "$p" ] || fail "$f: $p"; done <<<"$problems"

  # One line per product and subcomponent; a product without one is empty.
  while IFS=$'\t' read -r product sub; do
    [[ "$product" =~ ^pkg:oci/([a-z0-9.-]+)\?repository_url=${REGISTRY_REPO//./\\.}/([a-z0-9.-]+)$ ]] \
      && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
      || { fail "$f: product $product is not pkg:oci/<image>?repository_url=$REGISTRY_REPO/<image>"; continue; }
    repo=${BASH_REMATCH[1]}
    [ -n "${dirs_of[$repo]:-}" ] || { fail "$f: no image publishes to $REGISTRY_REPO/$repo"; continue; }
    [ -n "$sub" ] || { fail "$f: product $product names no package version (subcomponents)"; continue; }
    [[ "$sub" =~ ^pkg:apk/wolfi/([a-z0-9][a-z0-9._+-]*)@([0-9A-Za-z._+~-]+)$ ]] \
      || { fail "$f: subcomponent $sub is not pkg:apk/wolfi/<package>@<version>, without qualifiers"; continue; }
    pkg=${BASH_REMATCH[1]} ver=${BASH_REMATCH[2]} shipped=false
    for d in ${dirs_of[$repo]}; do
      jq -e --arg n "$pkg" --arg v "$ver" 'any(.contents.packages[]; .name == $n and .version == $v)' \
        "$IMAGES_DIR/$d/apko.lock.json" >/dev/null && shipped=true
    done
    $shipped || { echo "vex: stale: $vuln for $repo names $pkg $ver, which no $repo image ships now"; stale=$((stale + 1)); }
  done < <(jq -r '.statements[].products[]? | ."@id" as $p
    | if ((.subcomponents // []) | length) == 0 then [$p, ""] else (.subcomponents[] | [$p, (."@id" // "")]) end
    | @tsv' "$f")
done

shopt -s nullglob
evidence=("$VEX_DIR"/evidence/*.json)
shopt -u nullglob
for e in "${evidence[@]}"; do
  vuln=$(basename "$e" .json)
  jq -e . "$e" >/dev/null 2>&1 || { fail "$e: not valid JSON"; continue; }
  [ -f "$VEX_DIR/$vuln.json" ] || { fail "$e: no statements in $VEX_DIR/$vuln.json"; continue; }
  check=$(jq -r '.check // ""' "$e")
  [ -n "$check" ] && [ -f "$check" ] || fail "$e: check ${check:-(none)} does not exist"
  problems=$(jq -r --arg v "$vuln" --slurpfile doc "$VEX_DIR/$vuln.json" '
    def sha: type == "string" and test("^[0-9a-f]{40}$");
    [ (if .vulnerability != $v then "names \(.vulnerability), not \($v)" else empty end),
      (if (.issue // "" | test("^gh-[0-9]+$")) | not then "issue is not gh-<number>" else empty end),
      (if ((.upstream // []) | length) == 0 or any(.upstream[]; sha | not) then "upstream must list full commit SHAs" else empty end),
      (if ((.lines // {}) | length) == 0 then "no lines" else empty end),
      (.lines // {} | to_entries[] | .key as $pkg | .value as $l |
        (if ($l.status | IN("fixed", "affected", "not_affected")) | not then "\($pkg): unknown status \($l.status)" else empty end),
        (if $l.status == "fixed" and (($l.fix // []) | length) == 0 then "\($pkg): fixed without fix commits" else empty end),
        (if ($l.fix // [] | type) != "array" then "\($pkg): fix must be a list" else empty end),
        (if ($l.fix // [] | type) == "array" and any(($l.fix // [])[]; sha | not) then "\($pkg): fix commits must be full SHAs" else empty end),
        ([$doc[0].statements[] | select(any(.products[].subcomponents[]?; ."@id" | startswith("pkg:apk/wolfi/\($pkg)@")))] as $ss |
          (if ($ss | length) == 0 then "\($pkg): no statement names this package" else empty end),
          ($ss[] | select(.status != $l.status) | "\($pkg): a statement says \(.status), the evidence \($l.status)")))
    ] | .[]' "$e")
  while IFS= read -r p; do [ -z "$p" ] || fail "$e: $p"; done <<<"$problems"
done

echo "vex: ${#files[@]} file(s), ${#evidence[@]} with evidence, $fails problem(s), $stale stale statement(s)"
[ "$fails" = 0 ]
