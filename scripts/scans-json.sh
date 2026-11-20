#!/usr/bin/env bash
#
# scans-json.sh: the release's vulnerability findings, per image and
# platform, from both scanners, as one normalized JSON document. The
# release attaches it to the GitHub release, and the signed manifest
# records its sha256.
#
# Usage: scripts/scans-json.sh <records.json> <scan-dir> <release>
#   <records.json>: the scan stage's records (scan_db, scan_db_trivy, and
#   per image its name, digest, platforms and gate counts).
#   <scan-dir>: <image>.<arch>.{grype,trivy}.json. Output goes to stdout.
# scripts/cut-registry.sh writes both, and runs this before publishing.
set -euo pipefail

usage="usage: scans-json.sh <records.json> <scan-dir> <release>"
IMAGES_JSON="${1:?$usage}"
SCAN_DIR="${2:?$usage}"
RELEASE="${3:?$usage}"
[ -f "$IMAGES_JSON" ] || { echo "scans-json: $IMAGES_JSON missing" >&2; exit 1; }

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

images='{}'
grype_version='' trivy_version=''
while read -r name digest; do
  plats='{}'
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
    plats=$(jq -c --arg arch "$arch" --arg d "$pdigest" --argjson g "$gf" --argjson t "$tf" \
      '. + {($arch): {digest: $d, grype: $g, trivy: $t}}' <<<"$plats")
  done < <(jq -r --arg n "$name" '.images[] | select(.name == $n) | .platforms[] | "\(.arch) \(.digest)"' "$IMAGES_JSON")
  images=$(jq -c --arg n "$name" --arg d "$digest" --argjson p "$plats" \
    '. + {($n): {digest: $d, platforms: $p}}' <<<"$images")
done < <(jq -r '.images[] | "\(.name) \(.digest)"' "$IMAGES_JSON")

jq -n --arg release "$RELEASE" --arg gv "$grype_version" --arg tv "$trivy_version" \
  --arg gdb "$(jq -r .scan_db "$IMAGES_JSON")" --arg tdb "$(jq -r .scan_db_trivy "$IMAGES_JSON")" \
  --argjson images "$images" \
  '{schema: 1, release: $release,
    scanners: {grype: {version: $gv, db: $gdb}, trivy: {version: $tv, db: $tdb}},
    images: $images}'
