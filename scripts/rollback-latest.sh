#!/usr/bin/env bash
#
# rollback-latest.sh: point latest, and each image's line tag (node:24), back
# at an earlier, known-good release.
# See docs/maintaining.md, "Moving `latest` back".
#
# Downloads the release's signed manifest, verifies the manifest signature,
# verifies every image in it with verify-build.sh, and only then moves
# latest and the line tags to those digests. Nothing is moved if any check
# fails.
#
# Usage:
#   ./scripts/rollback-latest.sh <date-tag> [--dry-run]
#
# Env:
#   GH_REPO               repository holding the releases (default: MaliSec/temper)
#   MANIFEST              use this local manifest instead of downloading one;
#                         its bundle must sit beside it as <manifest>.sigstore.json
#   CERT_IDENTITY_REGEXP, CERT_OIDC_ISSUER
#                         passed to verify-build.sh; also used for the manifest
#   COSIGN_KEY            key-mode releases (forks): verify with this public key
# Needs: cosign, crane, jq, gh (unless MANIFEST is set), registry write access
# (docker login or crane auth login) for the image repositories.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=${1:?usage: rollback-latest.sh <date-tag> [--dry-run]}
DRY=0
case "$#:${2:-}" in
  1:) ;;
  2:--dry-run) DRY=1 ;;
  *) echo "usage: rollback-latest.sh <date-tag> [--dry-run]" >&2; exit 1 ;;
esac
[[ "$TAG" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]*)?$ ]] || { echo "not a date tag: $TAG" >&2; exit 1; }
GH_REPO=${GH_REPO:-MaliSec/temper}
# The manifest and every image must be signed by the run for this tag, not
# by any release: a replaced release asset cannot point the rollback at a
# different release.
CERT_IDENTITY_REGEXP=${CERT_IDENTITY_REGEXP:-"^https://github\\.com/MaliSec/temper/\\.github/workflows/temper-release-build\\.yml@refs/tags/${TAG//./\\.}\$"}
CERT_OIDC_ISSUER=${CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}
export CERT_IDENTITY_REGEXP CERT_OIDC_ISSUER
fail() { echo "ROLLBACK ABORTED: $*" >&2; exit 1; }
for t in cosign crane jq; do command -v "$t" >/dev/null || fail "$t required on PATH"; done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -n "${MANIFEST:-}" ]; then
  m="$MANIFEST"
else
  command -v gh >/dev/null || fail "gh required to download the manifest (or set MANIFEST)"
  gh release download "$TAG" --repo "$GH_REPO" --dir "$work" \
    --pattern "temper-${TAG}.manifest.yaml" --pattern "temper-${TAG}.manifest.yaml.sigstore.json" \
    || fail "cannot download the manifest for release $TAG from $GH_REPO"
  m="$work/temper-${TAG}.manifest.yaml"
fi
[ -f "$m" ] && [ -f "$m.sigstore.json" ] || fail "manifest or its bundle missing: $m(.sigstore.json)"

echo "==> manifest signature"
if [ -n "${COSIGN_KEY:-}" ]; then
  cosign verify-blob --key "$COSIGN_KEY" --insecure-ignore-tlog --bundle "$m.sigstore.json" "$m" >/dev/null 2>&1
else
  cosign verify-blob --bundle "$m.sigstore.json" --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$CERT_OIDC_ISSUER" --certificate-github-workflow-repository "$GH_REPO" "$m" >/dev/null 2>&1
fi || fail "the manifest for $TAG is not signed by the release workflow"
echo "    OK"

# Every image entry must name this release.
tags=$(sed -n 's/^    release: "\(.*\)"$/\1/p' "$m" | sort -u)
[ "$tags" = "$TAG" ] || fail "the manifest is for release(s) '$(tr '\n' ' ' <<<"$tags")', not $TAG"

# The manifest lists, per image, "repository:", "primary:", an optional
# "line:", then "digest:". Each output line is "<repo>@<digest> <primary>
# <line or empty>". An older line (primary: false) has no latest.
entries=$(awk '/^    repository: /{gsub(/"/,"",$2); r=$2; p="true"; l=""} /^    primary: /{p=$2}
  /^    line: /{gsub(/"/,"",$2); l=$2} /^    digest: /{gsub(/"/,"",$2); print r "@" $2 " " p " " l}' "$m")
pairs=$(cut -d' ' -f1 <<<"$entries")
[ -n "$pairs" ] || fail "no images found in $m"
rev=$(sed -n 's/^git_commit: "\(.*\)"$/\1/p' "$m")

echo "==> verify every image of $TAG"
while read -r pinned; do
  TEMPER_REV="$rev" ./scripts/verify-build.sh "$pinned" --manifest "$m" >/dev/null 2>&1 \
    || fail "$pinned does not verify (run: TEMPER_REV=$rev ./scripts/verify-build.sh $pinned --manifest $m)"
  echo "    OK  $pinned"
done <<<"$pairs"

echo "==> move latest and line tags"
moved=""
while read -r pinned primary line; do
  repo="${pinned%@*}"
  for t in $([ "$primary" = true ] && echo latest) ${line:+"$line"}; do
    if [ "$DRY" = 1 ]; then
      echo "    would tag $pinned as $t (currently $(crane digest "$repo:$t" 2>/dev/null || echo none))"
    else
      crane tag "$pinned" "$t" || fail "crane tag failed for $pinned as $t; tags may now be split across releases, rerun to finish"
      echo "    $t -> $pinned"
      moved="$moved ${repo##*/}:$t"
    fi
  done
done <<<"$entries"
if [ "$DRY" = 1 ]; then
  echo "dry run: nothing moved"
else
  echo "now on $TAG:${moved:- nothing}. Record the rollback in the release notes of the release you rolled back from."
fi
