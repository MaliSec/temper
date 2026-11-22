#!/usr/bin/env bash
#
# cut-registry.sh: publish a dated release of the project's images.
#
# Release workflow (keyless, SLSA Build Level 3; see temper-release-build.yml):
#   publish   build job, no signing credentials: policy check, Trivy + Grype
#             scan (policy §3.5, fail on any critical or known-exploited
#             finding), push, SBOM. Writes
#             $CUT_DIR/images.json and the image list to $GITHUB_OUTPUT.
#   (attest)  the workflow's attest job signs each digest and attests SLSA
#             provenance and the SBOM; this script is not involved.
#   finalize  release job: verifies every image with verify-build.sh, as a
#             consumer would, moves latest to this release if it is the
#             newest, and writes the release manifest.
# Local key-mode cut (set COSIGN_PRIVATE_KEY, no phase argument): publish,
# then sign and attest the SBOM with the key, verify, and write the manifest.
# Key-mode cuts carry no SLSA provenance.
#
# Usage (credentials come from the environment; see docs/verifying.md):
#   DATE=2026.11.19 ./scripts/cut-registry.sh publish
#   DATE=2026.11.19 ./scripts/cut-registry.sh finalize
#   COSIGN_PRIVATE_KEY=cosign.key IMAGE_REPO=... DATE=... ./scripts/cut-registry.sh
# Env:
#   IMAGE_REPO            images publish as $IMAGE_REPO/<name> (default: images
#                         in project.env); a key-mode fork sets its own
#   DATE                  required: immutable date tag, today or yesterday (UTC): YYYY.MM.DD, or
#                         YYYY.MM.DD.N for a further release the same day
#   PARTIAL_CUT=1         key mode only: cut a subset of the images (testing)
#   COSIGN_PRIVATE_KEY    key mode: path to the cosign private key (.key)
#   COSIGN_PASSWORD       key mode: required if the key is encrypted
#   GATE_VULNS            fail the cut on criticals or known-exploited findings (default: true)
#   TAR_DIR               image tars from build.sh (default: dist)
#   CERT_IDENTITY_REGEXP, CERT_OIDC_ISSUER
#                         finalize: passed through to verify-build.sh
set -euo pipefail
. "$(dirname "$0")/project.sh"

PHASE=${1:-}
# scan: the release's policy check and per-platform scans on local tars,
# with nothing published (make scan).
if [ "$PHASE" = scan ]; then
  IMAGE_REPO=${IMAGE_REPO:-local/local}; DATE=${DATE:-$(date -u +%Y.%m.%d)}
fi
IMAGE_REPO=${IMAGE_REPO:-$PROJECT_IMAGES}
[[ "$IMAGE_REPO" =~ $IMAGE_REPO_RE ]] || { echo "IMAGE_REPO '$IMAGE_REPO' is not <registry>/<path>" >&2; exit 1; }
REGISTRY=${IMAGE_REPO%%/*}
DATE=${DATE:?DATE required (e.g. 2026.11.19)}
[[ "$DATE" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]*)?$ ]] \
  || { echo "DATE must be YYYY.MM.DD or YYYY.MM.DD.N, got: $DATE" >&2; exit 1; }
# Signed by this release's run: a digest signed by an earlier release does
# not pass for this one.
CERT_IDENTITY_REGEXP=${CERT_IDENTITY_REGEXP:-"${SIGNER_RE}@refs/tags/${DATE//./\\.}\$"}
CERT_OIDC_ISSUER=${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}
OUT_DIR=${OUT_DIR:-dist}
TAR_DIR=${TAR_DIR:-${OUT_DIR}}
COSIGN=${COSIGN:-cosign}
SYFT=${SYFT:-syft}
GRYPE=${GRYPE:-grype}
TRIVY=${TRIVY:-trivy}
SCANNER_CONFIG="$TEMPER_HOME/scripts/scanners.yaml"
GATE_VULNS=${GATE_VULNS:-true}
CUT_DIR="${OUT_DIR}/registry-cut/${DATE}"
IMAGES_JSON="${CUT_DIR}/images.json"
export CERT_IDENTITY_REGEXP CERT_OIDC_ISSUER

case "$PHASE" in
  scan) SIGNING=none ;;
  publish|finalize)
    [ -z "${COSIGN_PRIVATE_KEY:-}" ] || { echo "the $PHASE phase is keyless; unset COSIGN_PRIVATE_KEY (a key-mode cut takes no phase)" >&2; exit 1; }
    # Keyless releases need the workflow's attest job between the phases.
    [ "${GITHUB_ACTIONS:-}" = "true" ] || { echo "the $PHASE phase runs only in the release workflow; set COSIGN_PRIVATE_KEY for a local cut" >&2; exit 1; }
    SIGNING=keyless ;;
  "")
    [ -n "${COSIGN_PRIVATE_KEY:-}" ] || {
      echo "keyless releases run only in the release workflow (phases: publish, finalize);" >&2
      echo "set COSIGN_PRIVATE_KEY for a local key-mode cut" >&2
      exit 1
    }
    [ -f "$COSIGN_PRIVATE_KEY" ] || { echo "cosign key not found: $COSIGN_PRIVATE_KEY" >&2; exit 1; }
    if head -1 "$COSIGN_PRIVATE_KEY" | grep -q 'BEGIN PUBLIC KEY'; then
      echo "$COSIGN_PRIVATE_KEY is a PUBLIC key — key mode needs the cosign PRIVATE key (.key)" >&2
      exit 1
    fi
    SIGNING=key ;;
  *) echo "unknown phase: $PHASE (scan | publish | finalize | none for a key-mode cut)" >&2; exit 1 ;;
esac

TEMPER_REV=${TEMPER_REV:-$(git rev-parse --verify -q HEAD || echo "unknown")}
export TEMPER_REV

# ---------------------------------------------------------------------------
# check_date: the release date must be a real calendar date, today or
# yesterday (UTC; yesterday for a run that crosses midnight). A date tag is
# never rewritten and latest follows the newest, so a mistyped future date
# would freeze latest until that day, and a past one would publish a
# release that can never become latest.
check_date() {
  local d="${DATE:0:10}" iso real
  iso="${d:0:4}-${d:5:2}-${d:8:2}"
  real=$(date -u -d "$iso" +%Y.%m.%d 2>/dev/null) && [ "$real" = "$d" ] \
    || { echo "DATE $DATE is not a calendar date" >&2; exit 1; }
  [ "$d" = "$(date -u +%Y.%m.%d)" ] || [ "$d" = "$(date -u -d yesterday +%Y.%m.%d)" ] \
    || { echo "DATE $DATE is not today ($(date -u +%Y.%m.%d) UTC); a release is tagged on the day it is cut" >&2; exit 1; }
}

scan_images() {
  for tool in crane "$SYFT" "$GRYPE" "$TRIVY" jq; do
    command -v "$tool" >/dev/null || { echo "$tool required on PATH" >&2; exit 1; }
  done
  [ -d "$TAR_DIR" ] || { echo "no $TAR_DIR/ — run ./scripts/build.sh first" >&2; exit 1; }
  mkdir -p "$CUT_DIR/sbom" "$CUT_DIR/scan"

  echo "==> stage 2: policy check"
  "$TEMPER_HOME/scripts/check-policy.sh"

  # Both scanners write a full JSON record per image to $CUT_DIR/scan/. The
  # gate fails on criticals from either scanner and on known-exploited
  # findings.
  echo "==> stage 3: vulnerability scan (pre-publish, trivy + grype)"
  # DB freshness is read from the local cache; the workflow refreshes it
  # before this script runs.
  TRIVY_DB_NOTE="trivy DB metadata not found (results recorded, freshness unknown)"
  TRIVY_DB_AGE=unknown
  trivy_cache="${XDG_CACHE_HOME:-$HOME/.cache}/trivy/db"
  if [ -f "$trivy_cache/metadata.json" ]; then
    TRIVY_DB_BUILT=$(sed -n 's/.*"UpdatedAt": *"\([^"]*\)".*/\1/p' "$trivy_cache/metadata.json" | head -1)
    TRIVY_DB_VERSION=$(sed -n 's/.*"Version": *\([0-9]*\).*/\1/p' "$trivy_cache/metadata.json" | head -1)
    [ -n "$TRIVY_DB_BUILT" ] || TRIVY_DB_BUILT=unknown
    # GNU date rejects trivy's fractional seconds ("...44.233Z"); strip them.
    TRIVY_DB_AGE=$(( ( $(date -u +%s) - $(date -u -d "$(echo "$TRIVY_DB_BUILT" | sed 's/\.[0-9]*Z$/Z/')" +%s 2>/dev/null || echo 0) ) / 86400 ))
    TRIVY_DB_NOTE="trivy DB built ${TRIVY_DB_BUILT}, schema ${TRIVY_DB_VERSION:-unknown}, age ${TRIVY_DB_AGE}d"
  fi
  echo "    $TRIVY_DB_NOTE"
  if [ "$TRIVY_DB_AGE" != "unknown" ] && [ "$TRIVY_DB_AGE" -gt 5 ]; then
    echo "    WARNING: trivy DB is stale (>5d) — scan results may be incomplete" >&2
  fi

  DB_NOTE="grype DB status unavailable (results recorded, freshness unknown)"
  DB_AGE="unknown"
  if db_status=$("$GRYPE" db status -c "$SCANNER_CONFIG" -o json 2>/dev/null) && [ "$(jq -r '.valid' <<<"$db_status")" = "true" ]; then
    DB_BUILT=$(jq -r '.built // "unknown"' <<<"$db_status")
    DB_VERSION=$(jq -r '.schemaVersion // "unknown"' <<<"$db_status")
    DB_AGE=$(( ( $(date -u +%s) - $(date -u -d "$DB_BUILT" +%s 2>/dev/null || echo 0) ) / 86400 ))
    DB_NOTE="grype DB built ${DB_BUILT}, schema ${DB_VERSION}, age ${DB_AGE}d"
  fi
  echo "    $DB_NOTE"
  if [ "$DB_AGE" != "unknown" ] && [ "$DB_AGE" -gt 5 ]; then
    echo "    WARNING: grype DB is stale (>5d) — scan results may be incomplete" >&2
  fi

  # Each image goes to a local staging registry as a multi-arch index, and
  # is scanned and SBOM'd there per platform; nothing is public yet.
  start_staging
  records=()
  for tar in "$TAR_DIR"/*.tar; do
    name=$(basename "$tar" .tar)
    case "$name" in *-debug) continue ;; esac
    "$TEMPER_HOME/scripts/tar-to-oci-layout.sh" "$tar" "$CUT_DIR/layout/$name"
    crane push --index "$CUT_DIR/layout/$name" "$STAGE/$name:stage" >/dev/null 2>&1 \
      || { echo "staging push failed: $name" >&2; exit 1; }
    digest=$(crane digest "$STAGE/$name:stage")
    staged="$STAGE/$name@$digest"
    plats=()
    crit_total=0 kev_total=0
    while read -r pdigest arch; do
      echo "    scanning $name/$arch (trivy, grype)"
      base="$CUT_DIR/scan/${name}.${arch}"
      # --skip-db-update: use the cached DB recorded above instead of
      # depending on the network mid-release.
      "$TRIVY" image --config "$SCANNER_CONFIG" --ignorefile /dev/null --insecure --platform "linux/$arch" \
        --skip-db-update --format json --scanners vuln \
        "$staged" > "$base.trivy.json" 2>"$base.trivy.stderr" \
        || { echo "trivy scan failed: $name/$arch — failing the cut (unscannable is not a pass)" >&2; tail -5 "$base.trivy.stderr" >&2; exit 1; }
      tsev() { jq "[.Results[]?.Vulnerabilities[]? | select((.Severity // \"UNKNOWN\") == \"$1\")] | length" "$base.trivy.json"; }
      tcrit=$(tsev CRITICAL)
      vulns_trivy="critical=${tcrit} high=$(tsev HIGH) medium=$(tsev MEDIUM) low=$(tsev LOW) unknown=$(tsev UNKNOWN)"
      echo "        trivy: ${vulns_trivy}"
      GRYPE_REGISTRY_INSECURE_USE_HTTP=true "$GRYPE" "registry:$staged" -c "$SCANNER_CONFIG" --platform "linux/$arch" -o json \
        > "$base.grype.json" 2>/dev/null \
        || { echo "grype scan failed: $name/$arch — failing the cut (unscannable is not a pass)" >&2; exit 1; }
      gsev() { jq "[.matches[]? | select((.vulnerability.severity // \"Unknown\") == \"$1\")] | length" "$base.grype.json"; }
      crit=$(gsev Critical)
      # On CISA's Known Exploited Vulnerabilities list, at any severity.
      gkev() { jq '[.matches[]? | select((.vulnerability.knownExploited // []) | length > 0)] | length' "$base.grype.json"; }
      kev=$(gkev)
      vulns_grype="critical=${crit} high=$(gsev High) medium=$(gsev Medium) low=$(gsev Low) negligible=$(gsev Negligible) unknown=$(gsev Unknown) kev=${kev}"
      echo "        grype: ${vulns_grype}"
      crit_total=$(( crit_total + tcrit + crit ))
      kev_total=$(( kev_total + kev ))
      SYFT_REGISTRY_INSECURE_USE_HTTP=true "$SYFT" "registry:$staged" -c "$SCANNER_CONFIG" --platform "linux/$arch" -o spdx-json \
        > "$CUT_DIR/sbom/${name}.${arch}.spdx.json" 2>/dev/null \
        || { echo "syft failed: $name/$arch" >&2; exit 1; }
      plats+=("$(jq -nc --arg arch "$arch" --arg digest "$pdigest" --arg g "$vulns_grype" --arg t "$vulns_trivy" \
        '{arch: $arch, digest: $digest, vulns_grype: $g, vulns_trivy: $t}')")
    done < <(crane manifest "$staged" | jq -r '.manifests[] | "\(.digest) \(.platform.architecture)"')
    [ ${#plats[@]} -gt 0 ] || { echo "$name: staged index lists no platforms" >&2; exit 1; }
    if [ "$GATE_VULNS" = "true" ] && { [ "$crit_total" != "0" ] || [ "$kev_total" != "0" ]; }; then
      echo "GATE: $name has ${crit_total} criticals (trivy + grype) and ${kev_total} known-exploited findings (grype) across its platforms — failing the cut BEFORE publish" >&2
      echo "      fix forward: repin the affected packages and rebuild; do not publish" >&2
      exit 1
    fi
    records+=("$(printf '%s\n' "${plats[@]}" | jq -sc --arg name "$name" --arg digest "$digest" \
      '{name: $name, digest: $digest, platforms: .,
        vulns_grype: ([.[] | "\(.arch): \(.vulns_grype)"] | join("; ")),
        vulns_trivy: ([.[] | "\(.arch): \(.vulns_trivy)"] | join("; "))}')")
  done

  # The release's VEX statements, and every finding behind the gate's
  # counts with the statement that covers it, if any; the manifest records
  # both files' sha256. Built here, so a malformed statement or a mismatch
  # stops the cut before anything is published. VEX does not change the
  # gate above, which runs on the scanners' own findings.
  "$TEMPER_HOME/scripts/vex-check.sh" vex images
  "$TEMPER_HOME/scripts/vex-merge.sh" vex "$DATE" > "$CUT_DIR/${PROJECT_NAME}-${DATE}.vex.json"
  printf '%s\n' "${records[@]}" | jq -s --arg scan_db "$DB_NOTE" --arg scan_db_trivy "$TRIVY_DB_NOTE" \
    '{scan_db: $scan_db, scan_db_trivy: $scan_db_trivy, images: .}' > "$CUT_DIR/scan/records.json"
  "$TEMPER_HOME/scripts/scans-json.sh" "$CUT_DIR/scan/records.json" "$CUT_DIR/scan" "$DATE" "$CUT_DIR/${PROJECT_NAME}-${DATE}.vex.json" \
    > "$CUT_DIR/${PROJECT_NAME}-${DATE}.scans.json"
}

publish() {
  check_date
  # A release is every image, each for both architectures.
  local want have r n l c
  # Each version line publishes to one repository with tags of its own: a
  # repo file must name a primary image and the image must have a version
  # line, and no two images may share a repository and line (they would
  # claim the same tags).
  local lines=()
  for c in images/*/apko.yaml; do
    n=$(basename "$(dirname "$c")"); r=$(image_repo "$n")
    l=$("$TEMPER_HOME/scripts/image-line.sh" "$n") || { echo "images/$n: no valid version line" >&2; exit 1; }
    if [ "$r" != "$n" ]; then
      [ -f "images/$r/apko.yaml" ] && [ ! -f "images/$r/repo" ] \
        || { echo "images/$n/repo names '$r', which is not a primary image directory" >&2; exit 1; }
      [ -n "$l" ] || { echo "images/$n publishes to '$r' as an older line but has no version line" >&2; exit 1; }
    fi
    lines+=("$r:$l")
  done
  r=$(printf '%s\n' "${lines[@]}" | sort | uniq -d)
  [ -z "$r" ] || { echo "two images claim the same repository and line: $r" >&2; exit 1; }
  want=$(for c in images/*/apko.yaml; do basename "$(dirname "$c")"; done | sort | tr '\n' ' ')
  have=$(for t in "$TAR_DIR"/*.tar; do n=$(basename "$t" .tar); case "$n" in *-debug) ;; *) echo "$n" ;; esac; done | sort | tr '\n' ' ')
  # PARTIAL_CUT=1 (key mode only) cuts a subset, for testing the pipeline.
  if [ "$have" != "$want" ]; then
    [ "$SIGNING" = key ] && [ "${PARTIAL_CUT:-0}" = 1 ] \
      || { echo "image tars ($have) are not the image set ($want)" >&2; exit 1; }
    echo "    PARTIAL_CUT: releasing $have only (key mode)"
  fi
  scan_images
  local rec
  for rec in "${records[@]}"; do
    archs=$(jq -r '[.platforms[].arch] | sort | join(" ")' <<<"$rec")
    [ "$archs" = "amd64 arm64" ] || { echo "$(jq -r .name <<<"$rec"): index platforms are '$archs', not amd64 and arm64" >&2; exit 1; }
  done

  # Date tags are never rewritten. Images are copied by digest only; the
  # date tag is added in stage 6, after signing, attestation and
  # verification, so a release that fails before then leaves no tag. Stage 6
  # onward is safe to re-run.
  echo "==> stage 4: copy each index to ${REGISTRY} by digest"
  for rec in "${records[@]}"; do
    name=$(jq -r .name <<<"$rec")
    repo=$(image_repo "$name")
    [ "$repo" != "$name" ] || require_tag_absent "${IMAGE_REPO}/${repo}:${DATE}"
    line=$("$TEMPER_HOME/scripts/image-line.sh" "$name")
    [ -z "$line" ] || require_tag_absent "${IMAGE_REPO}/${repo}:${line}-${DATE}"
  done
  local out=()
  for rec in "${records[@]}"; do
    name=$(jq -r .name <<<"$rec")
    digest=$(jq -r .digest <<<"$rec")
    ref="${IMAGE_REPO}/$(image_repo "$name")"
    echo "    $name → $ref@$digest"
    reg crane copy "$STAGE/$name@$digest" "${ref}@${digest}" \
      || { echo "crane copy failed: $name → ${ref}@${digest}" >&2; exit 1; }
    [ "$(crane digest "${ref}@${digest}")" = "$digest" ] || { echo "$name: published digest differs from the staged one" >&2; exit 1; }
    line=$("$TEMPER_HOME/scripts/image-line.sh" "$name")
    primary=$([ "$(image_repo "$name")" = "$name" ] && echo true || echo false)
    out+=("$(jq -c --arg repo "$ref" --arg line "$line" --argjson primary "$primary" \
      '. + {repository: $repo, line: $line, primary: $primary}' <<<"$rec")")
  done
  # The layouts were only for staging; the records the later jobs download
  # (scans, SBOMs, images.json) stay.
  rm -rf "$CUT_DIR/layout"

  printf '%s\n' "${out[@]}" | jq -s \
    --arg scan_db "$DB_NOTE" --arg scan_db_trivy "$TRIVY_DB_NOTE" --arg gate "$GATE_VULNS" \
    '{scan_db: $scan_db, scan_db_trivy: $scan_db_trivy, gate_vulns: $gate, images: .}' > "$IMAGES_JSON"
  # The signing subjects: each index (no SBOM: SBOMs describe a platform)
  # and each platform manifest with its SBOM.
  jq -c '[.images[] | ({name, repository, digest, sbom: ""},
          (. as $i | .platforms[] | {name: "\($i.name)/\(.arch)", repository: $i.repository, digest,
                                     sbom: "\($i.name).\(.arch).spdx.json"}))]' "$IMAGES_JSON" > "$CUT_DIR/subjects.json"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "images=$(cat "$CUT_DIR/subjects.json")" >> "$GITHUB_OUTPUT"
  fi
  echo "    $(jq '.images | length' "$IMAGES_JSON") images published; records in $CUT_DIR"
}

# start_staging: the local registry each image is scanned from before it
# is published. STAGE_REGISTRY names one already running (host:port).
STAGE_IMAGE=${STAGE_IMAGE:-docker.io/library/registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373}
start_staging() {
  if [ -n "${STAGE_REGISTRY:-}" ]; then STAGE="$STAGE_REGISTRY"; return; fi
  command -v docker >/dev/null || { echo "docker required for the staging registry (or set STAGE_REGISTRY)" >&2; exit 1; }
  local cid port i
  cid=$(docker run -d --rm -p 127.0.0.1::5000 "$STAGE_IMAGE") || { echo "cannot start the staging registry" >&2; exit 1; }
  trap "docker rm -f $cid >/dev/null 2>&1 || true" EXIT
  port=$(docker port "$cid" 5000/tcp | head -1 | sed 's/.*://')
  STAGE="localhost:${port}"
  for i in $(seq 1 30); do crane catalog "$STAGE" >/dev/null 2>&1 && return; sleep 1; done
  echo "staging registry at $STAGE did not come up" >&2
  exit 1
}

# require_tag_absent <repo:tag>: stop unless the registry reports the tag
# (or the repository) as not found. Any other error is not "absent".
# image_repo <image>: the repository an image directory publishes to. An
# older version line (images/node-24) names its repository in a repo file
# (node); without one, the repository is the directory name.
# reg CMD...: run a registry write, retrying transient errors (a new
# package's first pushes can fail); prints the last error on failure. Every
# write here is by digest or to a fixed tag, so a retry repeats it exactly.
reg() {
  local attempt err
  for attempt in 1 2 3; do
    if err=$("$@" 2>&1); then return 0; fi
    echo "attempt $attempt of 3 failed: $*" >&2
    printf '%s\n' "$err" | tail -5 | sed 's/^/      /' >&2
    [ "$attempt" = 3 ] || sleep $((attempt * 15))
  done
  return 1
}

image_repo() {
  if [ -f "images/$1/repo" ]; then tr -d '[:space:]' < "images/$1/repo"; else printf '%s' "$1"; fi
}

require_tag_absent() {
  local out
  if out=$(crane digest "$1" 2>&1); then
    echo "$1 already exists ($out); date tags are never rewritten: release as ${DATE}.N" >&2
    exit 1
  fi
  grep -qE 'MANIFEST_UNKNOWN|NAME_UNKNOWN|404' <<<"$out" && return 0
  # GHCR answers DENIED for a package that does not exist yet (every
  # package on the first release); the packages API tells the two apart.
  if [ "$REGISTRY" = ghcr.io ] && grep -qE 'DENIED|UNAUTHORIZED' <<<"$out" && command -v gh >/dev/null; then
    local path="${1#ghcr.io/}"; path="${path%:*}"
    local org="${path%%/*}" pkg="${path#*/}"
    if gh api "/orgs/${org}/packages/container/${pkg//\//%2F}" >/dev/null 2>&1; then :
    elif gh api "/orgs/${org}/packages/container/${pkg//\//%2F}" 2>&1 | grep -q 'HTTP 404'; then
      return 0
    fi
  fi
  echo "cannot check whether $1 exists: $out" >&2; exit 1
}

# tag_once <repo> <digest> <tag>: add an immutable tag. A tag already on this
# digest is a re-run of this finalize and counts as done; on any other digest
# it stops the release.
tag_once() {
  local repo="$1" digest="$2" t="$3" have
  if have=$(crane digest "${repo}:${t}" 2>/dev/null); then
    [ "$have" = "$digest" ] || { echo "${repo}:${t} already exists on ${have}; date tags are never rewritten" >&2; exit 1; }
    echo "    ${repo##*/}:${t} already on this release"
    return
  fi
  require_tag_absent "${repo}:${t}"
  reg crane tag "${repo}@${digest}" "$t" || { echo "crane tag failed: ${repo}@${digest} as $t" >&2; exit 1; }
}

# ---------------------------------------------------------------------------
key_sign() {
  command -v "$COSIGN" >/dev/null || { echo "$COSIGN required on PATH" >&2; exit 1; }
  echo "==> stage 5: sign + attest SBOM (key mode)"
  key_pub="${CUT_DIR}/cosign.pub"
  COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" "$COSIGN" public-key --key "$COSIGN_PRIVATE_KEY" > "$key_pub" 2>/dev/null \
    || { echo "cannot derive public key from $COSIGN_PRIVATE_KEY" >&2; exit 1; }
  export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
  local sign_args=(--key "$COSIGN_PRIVATE_KEY" --tlog-upload=false --use-signing-config=false)
  jq -c '.[]' "$CUT_DIR/subjects.json" | while read -r subj; do
    name=$(jq -r .name <<<"$subj")
    sbom=$(jq -r .sbom <<<"$subj")
    pinned="$(jq -r .repository <<<"$subj")@$(jq -r .digest <<<"$subj")"
    "$COSIGN" sign "${sign_args[@]}" --yes "$pinned" >/dev/null 2>&1 \
      || { echo "cosign sign failed: $name" >&2; exit 1; }
    [ -n "$sbom" ] || continue
    "$COSIGN" attest "${sign_args[@]}" --yes \
      --type spdxjson --predicate "$CUT_DIR/sbom/${sbom}" "$pinned" >/dev/null 2>&1 \
      || { echo "cosign attest spdxjson failed: $name" >&2; exit 1; }
  done
}

# ---------------------------------------------------------------------------
finalize() {
  [ -f "$IMAGES_JSON" ] || { echo "no $IMAGES_JSON — the publish phase's records are missing" >&2; exit 1; }
  echo "==> stage 6: verify every image as a consumer would"
  if [ "$SIGNING" = key ]; then export COSIGN_KEY="${CUT_DIR}/cosign.pub"; fi
  jq -c '.images[]' "$IMAGES_JSON" | while read -r img; do
    pinned="$(jq -r .repository <<<"$img")@$(jq -r .digest <<<"$img")"
    "$TEMPER_HOME/scripts/verify-build.sh" "$pinned" >/dev/null \
      || { echo "verification failed: $pinned" >&2; "$TEMPER_HOME/scripts/verify-build.sh" "$pinned" 2>&1 | tail -3 >&2; exit 1; }
    echo "    $(jq -r .name <<<"$img"): verified @ $(jq -r .digest <<<"$img")"
  done

  # The immutable tags: the date, and <line>-<date> for an image with a
  # version line (node:26-2026.11.19). An older line in the same repository
  # (node-24) gets only its <line>-<date>: the date tag is the primary's.
  echo "==> stage 6b: tag ${DATE}"
  jq -r '.images[] | "\(.repository) \(.digest) \(.primary) \(.line)"' "$IMAGES_JSON" | while read -r repo digest primary line; do
    for t in $([ "$primary" = true ] && echo "$DATE") ${line:+"${line}-${DATE}"}; do
      tag_once "$repo" "$digest" "$t"
    done
  done

  # latest follows the newest release only: if any image already has a
  # newer date tag (a re-run of an older release), latest moves for none.
  echo "==> stage 7: advance latest"
  LATEST_NOTE="advanced to ${DATE}"
  jq -e '[.images[] | select(.primary)] | length > 0' "$IMAGES_JSON" >/dev/null \
    || LATEST_NOTE="not advanced: no primary image in this release"
  while read -r repo; do
    newest=$(crane ls "$repo" | "$TEMPER_HOME/scripts/newest-date-tag.sh")
    if [ "$newest" != "$DATE" ]; then
      LATEST_NOTE="not advanced: ${repo##*/} has newer release ${newest}"
      break
    fi
  done < <(jq -r '.images[] | select(.primary) | .repository' "$IMAGES_JSON")
  if [[ "$LATEST_NOTE" == "advanced to ${DATE}" ]] && jq -e '[.images[] | select(.primary)] | length > 0' "$IMAGES_JSON" >/dev/null; then
    jq -r '.images[] | select(.primary) | "\(.repository)@\(.digest)"' "$IMAGES_JSON" | while read -r pinned; do
      reg crane tag "$pinned" latest || { echo "crane tag latest failed: $pinned" >&2; exit 1; }
    done
  fi
  echo "    latest: $LATEST_NOTE"

  # Each line tag (node:24) follows the newest release on its line, per
  # image. When an image moves to a new line, the old line tag stops moving.
  echo "==> stage 7b: advance line tags"
  LINE_NOTES="{}"
  while read -r repo digest line; do
    [ -n "$line" ] || continue
    newest=$(crane ls "$repo" | sed -n "s/^${line//./\\.}-//p" | "$TEMPER_HOME/scripts/newest-date-tag.sh")
    if [ "$newest" = "$DATE" ]; then
      reg crane tag "${repo}@${digest}" "$line" || { echo "crane tag failed: ${repo}@${digest} as $line" >&2; exit 1; }
      note="advanced to ${line}-${DATE}"
    else
      note="not advanced: ${repo##*/} has newer release ${line}-${newest}"
    fi
    echo "    ${repo##*/}:${line}: $note"
    LINE_NOTES=$(jq -c --arg r "$repo:$line" --arg n "$note" '. + {($r): $n}' <<<"$LINE_NOTES")
  done < <(jq -r '.images[] | "\(.repository) \(.digest) \(.line)"' "$IMAGES_JSON")

  SCANS="${CUT_DIR}/${PROJECT_NAME}-${DATE}.scans.json"
  [ -s "$SCANS" ] || { echo "no $SCANS — the scan phase's records are missing" >&2; exit 1; }
  SCANS_SHA256=$(sha256sum "$SCANS" | cut -d' ' -f1)
  VEX="${CUT_DIR}/${PROJECT_NAME}-${DATE}.vex.json"
  [ -s "$VEX" ] || { echo "no $VEX — the scan phase's records are missing" >&2; exit 1; }
  VEX_SHA256=$(sha256sum "$VEX" | cut -d' ' -f1)

  MANIFEST="${CUT_DIR}/${PROJECT_NAME}-${DATE}.manifest.yaml"
  if [ "$SIGNING" = keyless ]; then
    attestations="SLSA v1 build provenance + SPDX SBOM (GitHub attestations, verified)"
  else
    attestations="SPDX SBOM (cosign, verified); no SLSA provenance in key mode"
  fi
  {
    echo "# ${PROJECT_TITLE} release ${DATE} (scripts/cut-registry.sh)"
    echo "cut_at: \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
    echo "registry: \"${REGISTRY}\""
    echo "image_repository: \"${IMAGE_REPO}\""
    echo "git_commit: \"${TEMPER_REV}\""
    echo "scan_db: \"$(jq -r .scan_db "$IMAGES_JSON")\""
    echo "scan_db_trivy: \"$(jq -r .scan_db_trivy "$IMAGES_JSON")\""
    echo "gate_vulns: \"$(jq -r .gate_vulns "$IMAGES_JSON")\""
    echo "scans: \"$(basename "$SCANS")\""
    echo "scans_sha256: \"${SCANS_SHA256}\""
    echo "vex: \"$(basename "$VEX")\""
    echo "vex_sha256: \"${VEX_SHA256}\""
    echo "latest: \"${LATEST_NOTE}\""
    echo "signing: \"${SIGNING}\""
    if [ "$SIGNING" = keyless ]; then
      echo "signer_identity_regexp: \"${CERT_IDENTITY_REGEXP//\\/\\\\}\""
      echo "signer_oidc_issuer: \"${CERT_OIDC_ISSUER}\""
    fi
    echo "images:"
    jq -r --arg date "$DATE" --arg att "$attestations" --argjson ln "$LINE_NOTES" '.images[] |
      "  \(.name):\n    repository: \"\(.repository)\"\n" +
      (if .primary then "    tag: \"\($date)\"\n" else "" end) +
      "    release: \"\($date)\"\n    primary: \(.primary)\n" +
      (if .line != "" then "    line: \"\(.line)\"\n    line_tag: \"\(.line)-\($date)\"\n    line_latest: \"\($ln[.repository + ":" + .line])\"\n" else "" end) +
      "    digest: \"\(.digest)\"\n    vulns_at_cut: \"\(.vulns_grype)\"\n    vulns_trivy_at_cut: \"\(.vulns_trivy)\"\n    signed: true\n    attestations: \"\($att)\"\n    platforms:" +
      ([.platforms[] | "\n      \(.arch): \"\(.digest)\""] | join(""))' "$IMAGES_JSON"
  } > "$MANIFEST"
  echo "---"
  echo "release complete: $(jq '.images | length' "$IMAGES_JSON") images, release ${DATE} (${IMAGE_REPO})"
  echo "manifest: $MANIFEST (sign it and attach it, with $(basename "$SCANS") and $(basename "$VEX"), to the release for ${DATE}; do not commit them)"
}

case "$PHASE" in
  scan) scan_images; echo "scan passed: ${#records[@]} image(s); records in $CUT_DIR/scan" ;;
  publish) publish ;;
  finalize) finalize ;;
  "") publish; key_sign; finalize ;;
esac
