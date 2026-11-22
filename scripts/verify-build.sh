#!/usr/bin/env bash
#
# verify-build.sh: verify a published Temper image as a consumer would
# (docs/verifying.md): signature, provenance, SBOM, and digest in the release
# manifest. Needs only public material. Any failure exits 1.
#
# Usage:
#   ./scripts/verify-build.sh <registry/org/name@sha256:digest | name> [--date TAG] [--manifest FILE]
#
# TAG is an immutable release tag: the date (YYYY.MM.DD or YYYY.MM.DD.N), or
# <line>-<date> for an image with a version line (24-2026.11.19). Floating
# tags (latest, 24) are refused: verify the digest they point at instead.
#
# Examples:
#   ./scripts/verify-build.sh ghcr.io/malisec/temper/static@sha256:abc...
#   REGISTRY=ghcr.io IMAGE_ORG=malisec ./scripts/verify-build.sh temper/static --date 2026.11.19 \
#     --manifest temper-2026.11.19.manifest.yaml
#
# Keyless releases (default) need cosign, crane, jq and gh; key-mode cuts
# (COSIGN_KEY) need cosign, crane and jq, and carry no SLSA provenance.
# Env:
#   CERT_IDENTITY_REGEXP  expected signer (default: temper-release-build.yml at a date tag)
#   CERT_OIDC_ISSUER      default: GitHub Actions' token issuer
#   SOURCE_REPO           repository the attestations must come from (owner/repo)
#   COSIGN_KEY            cosign public key, for images cut in key mode
#   TEMPER_REV            commit the provenance must bind (default: HEAD)
#   TEMPER_MANIFEST       release manifest, same as --manifest
set -euo pipefail
cd "$(dirname "$0")/.."

REF=${1:?usage: verify-build.sh <registry/org/name@digest | name> [--date TAG] [--manifest FILE]}
shift
DATE_ARG=""
MANIFEST_ARG="${TEMPER_MANIFEST:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --date) DATE_ARG="${2:?--date needs a value}"; shift 2 ;;
    --manifest) MANIFEST_ARG="${2:?--manifest needs a file}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
IDENTITY_SET=${CERT_IDENTITY_REGEXP:+1}
CERT_IDENTITY_REGEXP=${CERT_IDENTITY_REGEXP:-'^https://github\.com/MaliSec/temper/\.github/workflows/temper-release-build\.yml@refs/tags/[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]*)?$'}
CERT_OIDC_ISSUER=${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}
SOURCE_REPO=${SOURCE_REPO:-MaliSec/temper}
# actions/attest records SPDX 2.3 SBOMs (syft's spdx-json) under this type.
SBOM_PREDICATE=${SBOM_PREDICATE:-https://spdx.dev/Document/v2.3}
command -v cosign >/dev/null 2>&1 || { echo "cosign not found — run: make install-tools" >&2; exit 1; }
command -v crane >/dev/null 2>&1 || { echo "crane not found — run: make install-tools" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

fail() { echo "VERIFY FAILED: $*" >&2; exit 1; }

if [ -n "$DATE_ARG" ]; then
  [[ "$DATE_ARG" =~ ^([0-9]+(\.[0-9]+)?-)?[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]*)?$ ]] \
    || fail "--date $DATE_ARG is not a release tag (YYYY.MM.DD[.N] or <line>-YYYY.MM.DD[.N])"
fi
# A bare name (flat <name> or nested temper/<name>) is composed under
# $REGISTRY/$IMAGE_ORG; a reference whose first component is a registry
# host (a dot, a port, or localhost) is used as given. A tag is resolved to
# a digest.
if [[ "$REF" != *@* ]]; then
  host="${REF%%/*}"
  if [[ "$REF" == */* && ( "$host" == *.* || "$host" == *:* || "$host" == localhost ) ]]; then
    :
  else
    REGISTRY=${REGISTRY:?REGISTRY env var required when verifying a bare image name}
    IMAGE_ORG=${IMAGE_ORG:?IMAGE_ORG env var required when verifying a bare image name}
    REF="${REGISTRY}/${IMAGE_ORG}/${REF}"
  fi
fi
if [[ "$REF" != *@sha256:* ]]; then
  [ -n "$DATE_ARG" ] || fail "$REF is a tag — pass --date <date tag> or verify a digest"
  base="${REF##*/}"
  [[ "$base" != *:* ]] || REF="${REF%:*}"   # a tag on the name; the port stays
  DIGEST=$(crane digest "$REF:$DATE_ARG") || fail "cannot resolve digest for $REF:$DATE_ARG"
  REF="${REF}@${DIGEST}"
fi
# With a release tag, the signature must come from that release's run, not
# any release: a tag moved to an older, validly signed digest then fails.
if [ -n "$DATE_ARG" ] && [ -z "$IDENTITY_SET" ]; then
  rel="${DATE_ARG##*-}"
  CERT_IDENTITY_REGEXP="^https://github\.com/MaliSec/temper/\.github/workflows/temper-release-build\.yml@refs/tags/${rel//./\\.}\$"
fi
echo "==> verifying $REF"
rev="${TEMPER_REV:-$(git rev-parse --verify -q HEAD || true)}"

# verify_ref <repo@digest> <label> <want_sbom 0|1>: signature and provenance,
# and the SBOM attestation for a platform manifest (an index has none).
verify_ref() {
  local ref="$1" label="$2" want_sbom="$3"
  if [ -n "${COSIGN_KEY:-}" ]; then
    [ -f "$COSIGN_KEY" ] || { echo "cosign public key not found at $COSIGN_KEY" >&2; exit 1; }
    how="public key $COSIGN_KEY"
    VERIFY_ARGS=(--key "$COSIGN_KEY" --insecure-ignore-tlog)
    cosign verify "${VERIFY_ARGS[@]}" "$ref" >/dev/null 2>&1 \
      || fail "cosign signature does not verify against the $how"
    echo "    ${label}signature: OK ($how)"
    # verify-attestation prints only attestations from the expected signer.
    if [ "$want_sbom" = 1 ]; then
      cosign verify-attestation "${VERIFY_ARGS[@]}" --type spdxjson "$ref" >/dev/null 2>&1 \
        || fail "no spdxjson SBOM attestation on $ref verifies against the $how"
      echo "    ${label}SBOM attestation (spdxjson): OK"
    fi
    echo "    ${label}provenance: none (key-mode cuts carry no SLSA provenance)"
    checked="signature ($how), SBOM attestation"
  else
    command -v gh >/dev/null 2>&1 || { echo "gh (GitHub CLI) required to verify attestations" >&2; exit 1; }
    how="release workflow identity"
    cosign verify --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
      --certificate-github-workflow-repository "$SOURCE_REPO" "$ref" >/dev/null 2>&1 \
      || fail "cosign signature does not verify against the $how"
    echo "    ${label}signature: OK ($how)"

    # The attestations must be signed by the release build workflow on a
    # GitHub-hosted runner; the provenance must also name the source commit.
    # --cert-identity-regex, not --signer-workflow: the latter matches the
  # workflow at any ref, the former only a release tag (or this release's).
  GH_ARGS=(--bundle-from-oci --repo "$SOURCE_REPO" --cert-identity-regex "$CERT_IDENTITY_REGEXP" --cert-oidc-issuer "$CERT_OIDC_ISSUER" --deny-self-hosted-runners)
    if [ -n "$rev" ] && [ "$rev" != "unknown" ]; then
      gh attestation verify "oci://$ref" "${GH_ARGS[@]}" --source-digest "$rev" >/dev/null 2>&1 \
        || fail "no SLSA v1 provenance on $ref from the release workflow binds commit $rev"
      echo "    ${label}provenance (SLSA v1) binds commit ${rev:0:12}: OK"
    else
      gh attestation verify "oci://$ref" "${GH_ARGS[@]}" >/dev/null 2>&1 \
        || fail "no SLSA v1 provenance on $ref from the release workflow"
      echo "    ${label}provenance (SLSA v1): OK; commit check skipped (no git rev available in this checkout)"
    fi
    if [ "$want_sbom" = 1 ]; then
      gh attestation verify "oci://$ref" "${GH_ARGS[@]}" --predicate-type "$SBOM_PREDICATE" >/dev/null 2>&1 \
        || fail "no SPDX SBOM attestation on $ref from the release workflow"
      echo "    ${label}SBOM attestation (SPDX): OK"
    fi
    checked="signature ($how), SLSA v1 provenance (commit-bound), SBOM attestation"
  fi
}

# A multi-arch release is an index: verify it, then every platform manifest
# it lists. Tags point at the index.
media=$(crane manifest "$REF" 2>/dev/null | jq -r '.mediaType // empty') || true
[ -n "$media" ] || fail "cannot read the manifest of $REF"
if [ "$media" = "application/vnd.oci.image.index.v1+json" ] || [ "$media" = "application/vnd.docker.distribution.manifest.list.v2+json" ]; then
  verify_ref "$REF" "index: " 0
  platforms=$(crane manifest "$REF" | jq -r '.manifests[] | "\(.digest) \(.platform.os)/\(.platform.architecture)"')
  [ -n "$platforms" ] || fail "index $REF lists no platform manifests"
  while read -r pd plat; do
    verify_ref "${REF%@*}@${pd}" "${plat}: " 1
  done <<<"$platforms"
  checked="$checked; index and $(wc -l <<<"$platforms") platform manifests"
else
  verify_ref "$REF" "" 1
fi

# The manifest is a release asset the consumer downloads; without one the
# check is skipped and reported as such.
if [ -n "$MANIFEST_ARG" ]; then
  [ -f "$MANIFEST_ARG" ] || fail "manifest not found: $MANIFEST_ARG"
  [ -f "$MANIFEST_ARG.sigstore.json" ] || fail "manifest signature bundle not found: $MANIFEST_ARG.sigstore.json"
  if [ -n "${COSIGN_KEY:-}" ]; then
    cosign verify-blob --key "$COSIGN_KEY" --insecure-ignore-tlog --bundle "$MANIFEST_ARG.sigstore.json" "$MANIFEST_ARG" >/dev/null 2>&1
  else
    cosign verify-blob --bundle "$MANIFEST_ARG.sigstore.json" --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$CERT_OIDC_ISSUER" --certificate-github-workflow-repository "$SOURCE_REPO" \
      "$MANIFEST_ARG" >/dev/null 2>&1
  fi || fail "the manifest $MANIFEST_ARG is not signed by the release workflow"
  echo "    manifest signature: OK"
  if [ -n "$DATE_ARG" ]; then
    grep -qE "^    release: \"${DATE_ARG##*-}\"$" "$MANIFEST_ARG" || fail "$MANIFEST_ARG is not the manifest of release ${DATE_ARG##*-}"
  fi
  # The entry for this repository and digest; with --date, that entry must
  # carry the tag verified (its date tag, or its <line>-<date> tag).
  digest="${REF##*@}" repo="${REF%@*}"
  awk -v repo="\"${repo,,}\"" -v d="\"${digest}\"" -v want="${DATE_ARG:+\"$DATE_ARG\"}" '
    /^  [^ ]/ {r=""; t=""; lt=""}
    /^    repository: / {r=tolower($2)} /^    tag: / {t=$2} /^    line_tag: / {lt=$2}
    /^    digest: / && r==repo && $2==d && (want=="" || t==want || lt==want) {ok=1}
    END {exit !ok}' "$MANIFEST_ARG" || fail "$repo@$digest is not listed in $MANIFEST_ARG${DATE_ARG:+ as $DATE_ARG}"
  echo "    $repo@$digest listed in $MANIFEST_ARG${DATE_ARG:+ as $DATE_ARG}: OK"
else
  echo "    NOTE: no release manifest supplied (--manifest) — digest-to-tag binding NOT cross-checked"
fi

echo "---"
echo "VERIFIED: $REF"
echo "  $checked"
