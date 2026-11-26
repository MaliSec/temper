#!/usr/bin/env bash
#
# scans-json.sh: the release's vulnerability findings, per image and
# platform, from both scanners, as one normalized JSON document. The
# release attaches it to the GitHub release, and the signed manifest
# records its sha256.
#
# Usage: scripts/scans-json.sh <records.json> <scan-dir> <release> [<vex.json>]
#   <records.json>: the scan stage's records (scan_db, scan_db_trivy, and
#   per image its name, digest, platforms and gate counts).
#   <scan-dir>: <image>.<arch>.{grype,trivy}.json. Output goes to stdout.
#   <vex.json>: the release's VEX document (scripts/vex-merge.sh). A finding
#   a statement covers (same vulnerability or alias, image repository, and
#   package name and version) carries that statement's status as "vex".
#   The counts stay the scanners' own: VEX does not change what the gate sees.
# scripts/cut-registry.sh writes all of them, and runs this before publishing.
set -euo pipefail

usage="usage: scans-json.sh <records.json> <scan-dir> <release> [<vex.json>]"
IMAGES_JSON=$(realpath -m "${1:?$usage}")
SCAN_DIR=$(realpath -m "${2:?$usage}")
RELEASE="${3:?$usage}"
VEX="${4:+$(realpath -m "$4")}"
IMAGES_DIR=${IMAGES_DIR:+$(realpath -m "$IMAGES_DIR")}
. "$(dirname "$0")/project.sh"
IMAGES_DIR=${IMAGES_DIR:-images}
REGISTRY_REPO=$PROJECT_IMAGES
[ -f "$IMAGES_JSON" ] || { echo "scans-json: $IMAGES_JSON missing" >&2; exit 1; }
# Documents go to jq as files: one command-line argument is limited to
# 128 KiB, and the findings outgrow it.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
echo '{"statements": []}' > "$work/vex.json"
if [ -n "$VEX" ]; then
  jq -c . "$VEX" > "$work/vex.json" || { echo "scans-json: $VEX is not valid JSON" >&2; exit 1; }
fi

# The statement covering a finding, if any: same vulnerability (or one of
# its aliases), the image's repository, and the finding's Wolfi package at
# its exact version.
with_vex='$vexes[0] as $vex | map(. as $f
  | ("pkg:oci/" + $repo + "?repository_url=" + $registry + "/" + $repo) as $product
  | ("pkg:apk/wolfi/" + $f.package.name + "@" + $f.package.version) as $sub
  | ([$f.id] + ($f.related // [])) as $ids
  | [$vex.statements[]
      | select(.vulnerability.name as $v | $ids | index([$v]))
      | select(any(.products[]?; ."@id" == $product and any(.subcomponents[]?; ."@id" == $sub)))][0] as $s
  | if ($s != null) and ($f.package.type == "apk" or $f.package.type == "wolfi")
    then . + {vex: ({status: $s.status} + ($s | with_entries(select(.key == "justification" or
          .key == "impact_statement" or .key == "action_statement" or .key == "status_notes"))))}
    else . end)'

grype_findings='[.matches[]? | {
  id: .vulnerability.id,
  related: [.relatedVulnerabilities[]?.id] | unique,
  severity: ((.vulnerability.severity // "unknown") | ascii_downcase),
  kev: ((.vulnerability.knownExploited // []) | length > 0),
  package: {name: .artifact.name, version: .artifact.version, type: .artifact.type, purl: .artifact.purl},
  fix_state: (if (.vulnerability.fix.state // "") == "" then "unknown" else .vulnerability.fix.state end),
  fixed_in: (.vulnerability.fix.versions // [])
}] | sort_by(.id, .package.name)'

trivy_findings='[.Results[]? as $r | $r.Vulnerabilities[]? | {
  id: .VulnerabilityID,
  severity: ((.Severity // "unknown") | ascii_downcase),
  package: {name: .PkgName, version: .InstalledVersion, type: $r.Type, purl: (.PkgIdentifier.PURL // null)},
  status: (if (.Status // "") == "" then "unknown" else .Status end),
  fixed_in: ((.FixedVersion // "") | split(", ") | map(select(. != "")))
}] | sort_by(.id, .package.name)'

echo '{}' > "$work/images.json"
grype_version='' trivy_version=''
while read -r name digest; do
  echo '{}' > "$work/plats.json"
  while read -r arch pdigest; do
    g="$SCAN_DIR/${name}.${arch}.grype.json"
    t="$SCAN_DIR/${name}.${arch}.trivy.json"
    [ -f "$g" ] && [ -f "$t" ] || { echo "scans-json: scan records for $name/$arch missing" >&2; exit 1; }
    [ -n "$grype_version" ] || grype_version=$(jq -r '.descriptor.version // "unknown"' "$g")
    [ -n "$trivy_version" ] || trivy_version=$(jq -r '.Trivy.Version // "unknown"' "$t")
    gf=$(jq -c "$grype_findings" "$g")
    tf=$(jq -c "$trivy_findings" "$t")
    # The findings must add up to the counts the gate recorded.
    for s in grype:"$gf" trivy:"$tf"; do
      tool=${s%%:*} found=${s#*:}
      want=$(jq -r --arg n "$name" --arg a "$arch" --arg k "vulns_$tool" \
        '.images[] | select(.name == $n) | .platforms[] | select(.arch == $a) | .[$k]
         | [scan("(critical|high|medium|low|negligible|unknown)=([0-9]+)") | .[1] | tonumber] | add' "$IMAGES_JSON")
      got=$(jq 'length' <<<"$found")
      [ "$want" = "$got" ] || { echo "scans-json: $name/$arch $tool lists $got findings, the gate counted $want" >&2; exit 1; }
    done
    repo=$name; [ ! -f "$IMAGES_DIR/$name/repo" ] || repo=$(tr -d '[:space:]' < "$IMAGES_DIR/$name/repo")
    jq -c --arg repo "$repo" --arg registry "$REGISTRY_REPO" --slurpfile vexes "$work/vex.json" "$with_vex" <<<"$gf" > "$work/g.json"
    jq -c --arg repo "$repo" --arg registry "$REGISTRY_REPO" --slurpfile vexes "$work/vex.json" "$with_vex" <<<"$tf" > "$work/t.json"
    jq -c --arg arch "$arch" --arg d "$pdigest" --slurpfile g "$work/g.json" --slurpfile t "$work/t.json" \
      '. + {($arch): {digest: $d, grype: $g[0], trivy: $t[0]}}' "$work/plats.json" > "$work/next.json"
    mv "$work/next.json" "$work/plats.json"
  done < <(jq -r --arg n "$name" '.images[] | select(.name == $n) | .platforms[] | "\(.arch) \(.digest)"' "$IMAGES_JSON")
  jq -c --arg n "$name" --arg d "$digest" --slurpfile p "$work/plats.json" \
    '. + {($n): {digest: $d, platforms: $p[0]}}' "$work/images.json" > "$work/next.json"
  mv "$work/next.json" "$work/images.json"
done < <(jq -r '.images[] | "\(.name) \(.digest)"' "$IMAGES_JSON")

jq -n --arg release "$RELEASE" --arg gv "$grype_version" --arg tv "$trivy_version" \
  --arg gdb "$(jq -r .scan_db "$IMAGES_JSON")" --arg tdb "$(jq -r .scan_db_trivy "$IMAGES_JSON")" \
  --slurpfile images "$work/images.json" \
  '{schema: 2, release: $release,
    scanners: {grype: {version: $gv, db: $gdb}, trivy: {version: $tv, db: $tdb}},
    images: $images[0]}'
