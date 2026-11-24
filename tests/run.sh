#!/usr/bin/env bash
#
# run.sh: local tests for the scripts and the build workflow. Runs
# check-policy.sh against synthetic OCI tars and checks the fail-closed
# paths of verify-build.sh and cut-registry.sh. No registry, network or keys.
#
# Usage: ./tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1" >&2; }
# expect_fail <desc> <cmd...>: command must exit non-zero
expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$desc (expected failure, got success)"; else ok "$desc"; fi
}
# expect_ok <desc> <cmd...>
expect_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc (expected success, got failure)"; fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# make_oci_tar <outfile> <run_as_uid> <file-spec...>
#   file-spec: "path mode" e.g. "usr/bin/app 0755" or "usr/bin/su 6755"
make_oci_tar() {
  # Specs: "path mode" (a file), "path ln:target" (a hard link to target in
  # the same layer); "--layer" starts the next layer.
  local out="$1" uid="$2"; shift 2
  local dir="$TMP/rootfs.$$"
  rm -rf "$dir"; mkdir -p "$dir/rootfs" "$dir/blobs/sha256"

  local spec path mode ldigest
  local ldigests=()
  seal_layer() {
    (cd "$dir/rootfs" && tar --sort=name -cf "$dir/blobs/layer.tar" .)
    ldigest=$(sha256sum "$dir/blobs/layer.tar" | cut -d' ' -f1)
    mv "$dir/blobs/layer.tar" "$dir/blobs/sha256/$ldigest"
    ldigests+=("sha256:$ldigest")
    rm -rf "$dir/rootfs"; mkdir -p "$dir/rootfs"
  }
  for spec in "$@"; do
    if [ "$spec" = --layer ]; then seal_layer; continue; fi
    path="${spec%% *}"; mode="${spec##* }"
    mkdir -p "$dir/rootfs/$(dirname "$path")"
    if [[ "$mode" == ln:* ]]; then
      ln "$dir/rootfs/${mode#ln:}" "$dir/rootfs/$path"
    else
      : > "$dir/rootfs/$path"
      chmod "$mode" "$dir/rootfs/$path"
    fi
  done
  seal_layer

  local cfg="$TMP/config.json"
  jq -n --arg uid "$uid" '{config: {User: $uid}, rootfs: {diff_ids: $ARGS.positional}}' \
    --args "${ldigests[@]}" > "$cfg"
  local cdigest
  cdigest=$(sha256sum "$cfg" | cut -d' ' -f1)
  cp "$cfg" "$dir/blobs/sha256/$cdigest"

  local man="$TMP/manifest.json"
  jq -n --arg cd "$cdigest" '{config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: ("sha256:" + $cd)}, layers: []}' > "$man"
  local mdigest
  mdigest=$(sha256sum "$man" | cut -d' ' -f1)
  cp "$man" "$dir/blobs/sha256/$mdigest"

  jq -n --arg md "$mdigest" '{manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: ("sha256:" + $md)}]}' > "$dir/index.json"
  echo '{"imageLayoutVersion":"1.0.0"}' > "$dir/oci-layout"

  (cd "$dir" && tar -cf "$out" index.json oci-layout blobs)
  rm -rf "$dir"
}

echo "== check-policy.sh: policy enforcement behavior =="
POLICY="$TMP/policy-dist"; mkdir -p "$POLICY"

make_oci_tar "$POLICY/good.tar" 65532 "usr/bin/app 0755" "etc/passwd 0644"
expect_ok "nonroot tar with no setuid passes" ./scripts/check-policy.sh "$POLICY/good.tar"

make_oci_tar "$POLICY/setuid.tar" 65532 "usr/bin/app 0755" "usr/bin/su 6755"
expect_fail "setuid file is a policy violation" ./scripts/check-policy.sh "$POLICY/setuid.tar"

make_oci_tar "$POLICY/root.tar" 0 "usr/bin/app 0755"
expect_fail "run-as root is a policy violation" ./scripts/check-policy.sh "$POLICY/root.tar"

make_oci_tar "$POLICY/apk.tar" 65532 "usr/bin/app 0755" "usr/sbin/apk 0755"
expect_fail "apk in a runtime image is a policy violation" ./scripts/check-policy.sh "$POLICY/apk.tar"

make_oci_tar "$POLICY/busybox.tar" 65532 "usr/bin/busybox 0755"
expect_fail "busybox outside base-shell is a policy violation" ./scripts/check-policy.sh "$POLICY/busybox.tar"
make_oci_tar "$POLICY/bash.tar" 65532 "usr/bin/bash 0755"
expect_fail "bash outside the shell tier is a policy violation" ./scripts/check-policy.sh "$POLICY/bash.tar"
make_oci_tar "$POLICY/sh.tar" 65532 "bin/sh 0755"
expect_fail "bin/sh outside the shell tier is a policy violation" ./scripts/check-policy.sh "$POLICY/sh.tar"
make_oci_tar "$POLICY/go-builder.tar" 65532 "usr/bin/busybox 0755"
expect_ok "builder images may carry busybox" ./scripts/check-policy.sh "$POLICY/go-builder.tar"

make_oci_tar "$POLICY/app-debug.tar" 65532 "usr/bin/busybox 0755" "usr/sbin/apk 0755"
expect_ok "debug variant may carry busybox+apk" ./scripts/check-policy.sh "$POLICY/app-debug.tar"
make_oci_tar "$POLICY/app2-debug.tar" 65532 "usr/bin/busybox 6755"
expect_fail "debug variant still rejects setuid" ./scripts/check-policy.sh "$POLICY/app2-debug.tar"

expect_fail "policy check with no tars fails closed" env OUT_DIR="$TMP/empty-dist" ./scripts/check-policy.sh
echo "not an oci tar" > "$POLICY/garbage.tar"
expect_fail "garbage tar fails (uninspectable is not a pass)" ./scripts/check-policy.sh "$POLICY/garbage.tar"

echo "== release-boundary: verify-build.sh fail-closed interfaces =="
expect_fail "verify without args fails" ./scripts/verify-build.sh
mkdir -p "$TMP/vstub"
printf '#!/bin/sh\nexit 0\n' > "$TMP/vstub/cosign"
printf '#!/bin/sh\n[ "$1" = manifest ] && echo %s\nexit 0\n' "'{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"}'" > "$TMP/vstub/crane"
chmod +x "$TMP/vstub/"*
out=$(PATH="$TMP/vstub:$PATH" COSIGN_KEY=tests/fixtures/no-such-key.pub ./scripts/verify-build.sh r/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 2>&1 || true)
grep -q 'cosign public key not found' <<<"$out" && ok "verify with a missing public key fails on the key" \
  || fail "verify with a missing public key: $out"

echo "== release-boundary: cut-registry.sh argument contracts =="
for r in reg.example Reg.example/o reg.example/o/ "https://reg.example/o"; do
  expect_fail "cut with IMAGE_REPO=$r fails" env IMAGE_REPO="$r" DATE=2026.01.01 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
done
expect_fail "cut without DATE fails" env IMAGE_REPO=reg.example/o COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
expect_fail "key-mode cut with a missing key file fails" env IMAGE_REPO=reg.example/o DATE=2026.01.01 COSIGN_PRIVATE_KEY=tests/fixtures/no-such.key ./scripts/cut-registry.sh
# Outside the release workflow, a keyless cut must stop before stage 2.
for phase in "" publish finalize; do
  out=$(env -u GITHUB_ACTIONS -u COSIGN_PRIVATE_KEY \
    IMAGE_REPO=reg.example/o DATE=2026.01.01 ./scripts/cut-registry.sh $phase 2>&1) && rc=0 || rc=$?
  if [ "$rc" != 0 ] && ! echo "$out" | grep -q 'stage 2'; then
    ok "keyless cut (${phase:-no phase}) outside the release workflow fails before any stage runs"
  else
    fail "keyless cut (${phase:-no phase}) outside the release workflow did not fail early"
  fi
done
expect_fail "unknown cut phase fails" env IMAGE_REPO=reg.example/o DATE=2026.01.01 ./scripts/cut-registry.sh bogus
expect_fail "malformed DATE tag fails" env IMAGE_REPO=reg.example/o DATE=2026.1.1 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
expect_fail "malformed same-day suffix fails" env IMAGE_REPO=reg.example/o DATE=2026.01.01-1 COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
for t in 2026.01.01.0 2026.01.01.01; do
  expect_fail "same-day suffix $t fails (it would tie with the plain date)" env IMAGE_REPO=reg.example/o DATE=$t COSIGN_PRIVATE_KEY=/dev/null ./scripts/cut-registry.sh
  expect_fail "rollback to $t fails" ./scripts/rollback-latest.sh $t --dry-run
done
expect_fail "build.sh --images with a filter that matches nothing fails" env OUT_DIR="$TMP/nomatch" ./scripts/build.sh --images --image nosuch-image
expect_fail "build.sh --lock with a filter that matches nothing fails" ./scripts/build.sh --lock --image nosuch-image
out=$(./scripts/rollback-latest.sh 2026.01.01 --dryrun 2>&1 || true)
grep -q '^usage: rollback-latest.sh' <<<"$out" && ok "rollback-latest refuses an unknown argument (a mistyped --dry-run never moves tags)" \
  || fail "rollback-latest accepted an unknown argument: $out"
mkdir -p "$TMP/vstub"; printf '#!/bin/sh\nexit 1\n' > "$TMP/vstub/cosign"; cp "$TMP/vstub/cosign" "$TMP/vstub/crane"; chmod +x "$TMP/vstub/"*
out=$(PATH="$TMP/vstub:$PATH" ./scripts/verify-build.sh localhost:1/o/temper/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 --date garbage 2>&1 || true)
grep -q 'is not a release tag' <<<"$out" && ok "verify-build validates --date with a digest reference" \
  || fail "verify-build accepted a malformed --date with a digest: $out"
out=$(PATH="$TMP/vstub:$PATH" ./scripts/verify-build.sh localhost:1/o/temper/x@sha256:0000000000000000000000000000000000000000000000000000000000000000 --date 2026.01.01.0 2>&1 || true)
grep -q 'is not a release tag' <<<"$out" && ok "verify-build refuses a .0 same-day suffix" \
  || fail "verify-build accepted --date 2026.01.01.0: $out"
# An older line (a repo file) must have a version line of its own.
CUT="$TMP/cutrepo"; mkdir -p "$CUT/images"; cp -r scripts project.env "$CUT/"; cp -r images/node "$CUT/images/node"
mkdir -p "$CUT/images/node-x"; cp images/static/apko.yaml "$CUT/images/node-x/"; echo node > "$CUT/images/node-x/repo"
echo dummy > "$TMP/dummy.key"
out=$(cd "$CUT" && env IMAGE_REPO=localhost:1/o DATE="$(date -u +%Y.%m.%d)" OUT_DIR="$TMP/cutrepo-dist" \
  COSIGN_PRIVATE_KEY="$TMP/dummy.key" TEMPER_REV=unknown ./scripts/cut-registry.sh 2>&1 || true)
grep -q 'publishes to .node. as an older line but has no version line' <<<"$out" \
  && ok "the cut refuses an older-line image without a version line" \
  || fail "the cut accepted an older-line image without a version line: $(tail -2 <<<"$out")"

echo "== release workflow: SLSA Build Level 3 layout =="
RB=.github/workflows/temper-release-build.yml
job() { awk -v j="$1" '$0 ~ "^  "j":$" {f=1; next} f && /^  [a-z-]+:$/ {exit} f' "$RB"; }
# Each check below reads one job; a missing or renamed job must fail, not
# pass because the job's text is empty.
for j in build attest evidence-suites evidence-capture evidence-bundle release; do
  grep -q "^  $j:$" "$RB" || fail "release workflow has no '$j' job"
done
job build | grep -q 'id-token' \
  && fail "the build job can mint OIDC tokens (signing credentials reach build steps)" \
  || ok "the build job has no id-token permission"
{ job attest; cat .github/actions/attest/action.yml; } | grep -qE 'build\.sh|apko|melange|syft|trivy|grype' \
  && fail "the attest job runs build or scan steps" \
  || ok "the attest job runs no build or scan steps"
job evidence-capture | grep -q 'id-token' \
  && fail "the evidence capture job can mint OIDC tokens" \
  || ok "the evidence capture job has no id-token permission"
job evidence-bundle | grep -qE 'build\.sh|apko|melange|capture/run\.sh' \
  && fail "the evidence bundle job (which attests) runs build steps" \
  || ok "the evidence bundle job only packs and attests"
job release | grep -q 'needs: \[build, attest, evidence-bundle\]' \
  && ok "the release publishes tags only after the evidence bundle is attested" \
  || fail "the release job does not wait for the evidence bundle"
job attest | grep -q 'uses: ./.github/actions/attest' && grep -q 'uses: actions/attest@' .github/actions/attest/action.yml \
  && ok "provenance is generated by actions/attest, not by the build" \
  || fail "the attest job does not use actions/attest"
grep -rq 'slsa.dev/provenance/v0.2' scripts .github \
  && fail "a hand-written v0.2 provenance predicate remains" \
  || ok "no hand-written provenance predicate"
grep -q 'uses: ./.github/workflows/temper-release-build.yml' .github/workflows/temper-release.yml \
  && ok "temper-release.yml calls the reusable release workflow" \
  || fail "temper-release.yml does not call temper-release-build.yml"
grep -q -- '--cert-identity-regex "$CERT_IDENTITY_REGEXP"' scripts/verify-build.sh && ! grep -v '^ *#' scripts/verify-build.sh | grep -q -- '--signer-workflow' \
  && ok "verify-build pins the attestation signer to a release tag (not the workflow at any ref)" \
  || fail "verify-build does not pin the attestation signer identity"

# The workflow is public and reusable: called from another repository, it
# would sign with Temper's identity. Every job refuses to run elsewhere,
# and every keyless verification also pins the source repository.
guard_bad=""
for j in $(awk '/^jobs:$/{f=1; next} f && /^  [a-z-]+:$/{sub(/:$/,""); print $1}' "$RB"); do
  job "$j" | grep -qx "    if: github.repository == 'MaliSec/temper'" || guard_bad="$guard_bad $j"
done
[ -z "$guard_bad" ] && ok "every release job runs only in MaliSec/temper" \
  || fail "release jobs that would run when called from another repository:$guard_bad"
# pin_bad <file>...: the keyless cosign verify commands (joined across
# continuation lines) whose source repository is missing or is not
# MaliSec/temper: the literal, or "$SOURCE_REPO"/"$GH_REPO", which
# default to it (checked below). An empty value restricts nothing.
pin_bad() {
  awk '/cosign verify/ && !/^ *#/ {c=$0; while (c ~ /\\$/ && (getline l) > 0) c = c " " l; print FILENAME": "c}' "$@" \
    | grep -E -- '--certificate-identity' \
    | grep -vE -- '--certificate-github-workflow-repository[ =](MaliSec/temper|"\$SOURCE_REPO"|"\$GH_REPO")( |$)' || true
}
bad=$(pin_bad scripts/*.sh docs/*.md README.md)
[ -z "$bad" ] && ok "every keyless cosign verification pins MaliSec/temper as the source repository" \
  || fail "keyless verification without MaliSec/temper as the source repository:"$'\n'"$bad"
grep -qx 'repo=MaliSec/temper' project.env \
  && grep -qx 'SOURCE_REPO=${SOURCE_REPO:-$PROJECT_REPO}' scripts/verify-build.sh \
  && grep -qx 'GH_REPO=${GH_REPO:-$PROJECT_REPO}' scripts/rollback-latest.sh \
  && ok "verify-build and rollback-latest default the source repository to MaliSec/temper" \
  || fail "SOURCE_REPO or GH_REPO no longer defaults to MaliSec/temper"
mkdir -p "$TMP/pin"
for v in "''" '""' 'MaliSec/other' 'MaliSec/temper-apps' '"$OTHER"' '\'; do
  printf 'cosign verify --certificate-identity-regexp "$ID" \\\n  --certificate-github-workflow-repository %s x\n' "$v" > "$TMP/pin/f.sh"
  [ -n "$(pin_bad "$TMP/pin/f.sh")" ] && ok "a source repository of $v is refused" || fail "a source repository of $v passed the check"
done
printf 'cosign verify --certificate-identity-regexp "$ID" x\n' > "$TMP/pin/f.sh"
[ -n "$(pin_bad "$TMP/pin/f.sh")" ] && ok "a verification without a source repository is refused" \
  || fail "a verification without a source repository passed the check"


echo "== another repository's releases: scripts/project.sh and .github/actions =="
# A second project, released with these scripts as the actions run them:
# from the project's own checkout, with the scripts in Temper's.
TH=$(pwd)
APPS="$TMP/apps"; mkdir -p "$APPS/images/app" "$APPS/vex" "$TMP/astub"
cp images/static/apko.yaml "$APPS/images/app/"
printf 'name=temper-apps\ntitle=Temper Apps\nrepo=MaliSec/temper-apps\nrelease_workflow=temper-apps-release-build.yml\nimages=r.example/malisec/temper-apps\n' > "$APPS/project.env"
apps() { (cd "$APPS" && env TEMPER_PROJECT_DIR="$APPS" "$@"); }
d0=sha256:0000000000000000000000000000000000000000000000000000000000000000
temper_id='https://github.com/MaliSec/temper/.github/workflows/temper-release-build.yml@refs/tags/2026.01.01'
apps_id='https://github.com/MaliSec/temper-apps/.github/workflows/temper-apps-release-build.yml@refs/tags/2026.01.01'
# Stubs that record their arguments: crane resolves :2026.01.01 and finds
# no other tag, gh and cosign accept everything.
cat > "$TMP/astub/cosign" <<STUB
#!/bin/sh
echo "\$@" >> "$TMP/astub/cosign.log"
STUB
cat > "$TMP/astub/crane" <<STUB
#!/bin/sh
echo "\$@" >> "$TMP/astub/crane.log"
case "\$1:\$2" in
  manifest:*) echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json"}' ;;
  digest:*:2026.01.01) echo $d0 ;;
  digest:*) echo MANIFEST_UNKNOWN; exit 1 ;;
esac
exit 0
STUB
cat > "$TMP/astub/gh" <<STUB
#!/bin/sh
echo "\$@" >> "$TMP/astub/gh.log"
STUB
chmod +x "$TMP/astub/"*
stubs() { : > "$TMP/astub/cosign.log"; : > "$TMP/astub/crane.log"; : > "$TMP/astub/gh.log"; }
# signer_re: the identity regex of the first cosign call.
signer_re() { sed -n 's/.*--certificate-identity-regexp \([^ ]*\).*/\1/p' "$TMP/astub/cosign.log" | head -1; }
stubs; PATH="$TMP/astub:$PATH" TEMPER_REV=unknown ./scripts/verify-build.sh "r.example/o/x@$d0" >/dev/null 2>&1 || true
re_temper=$(signer_re)
stubs; apps env PATH="$TMP/astub:$PATH" TEMPER_REV=unknown "$TH/scripts/verify-build.sh" "r.example/o/x@$d0" >/dev/null 2>&1 || true
re_apps=$(signer_re)
if [ -n "$re_temper" ] && [ -n "$re_apps" ] \
   && grep -qE "$re_temper" <<<"$temper_id" && ! grep -qE "$re_temper" <<<"$apps_id" \
   && grep -qE "$re_apps" <<<"$apps_id" && ! grep -qE "$re_apps" <<<"$temper_id" \
   && grep -q -- '--certificate-github-workflow-repository MaliSec/temper-apps ' "$TMP/astub/cosign.log" \
   && grep -q -- '--repo MaliSec/temper-apps ' "$TMP/astub/gh.log"; then
  ok "each project's verify-build accepts its own release signer and repository, not the other's"
else fail "project signers: temper '$re_temper', apps '$re_apps'"; fi
# A bare name and --date: the project's images, signed for that tag only.
stubs; out=$(apps env PATH="$TMP/astub:$PATH" TEMPER_REV=unknown "$TH/scripts/verify-build.sh" app --date 2026.01.01 2>&1) || true
want='^https://github\.com/MaliSec/temper-apps/\.github/workflows/temper-apps-release-build\.yml@refs/tags/2026\.01\.01$'
[ "$(signer_re)" = "$want" ] && grep -q "r.example/malisec/temper-apps/app@$d0\$" "$TMP/astub/cosign.log" \
  && grep -qF "signer: $want, from MaliSec/temper-apps" <<<"$out" \
  && ok "verify-build --date looks the name up in the project's images and names the release's signer" \
  || fail "verify-build --date for another project: signer '$(signer_re)', output: $(head -3 <<<"$out")"
# Dots in the repository and workflow are literal.
mkdir -p "$TMP/dotproj"; sed -e 's/^repo=.*/repo=MaliSec\/temper.apps/' -e 's/^release_workflow=.*/release_workflow=r.yml/' \
  "$APPS/project.env" > "$TMP/dotproj/project.env"
stubs; (cd "$TMP/dotproj" && env TEMPER_PROJECT_DIR="$TMP/dotproj" PATH="$TMP/astub:$PATH" TEMPER_REV=unknown \
  "$TH/scripts/verify-build.sh" "r.example/o/x@$d0" >/dev/null 2>&1) || true
re=$(signer_re)
[ -n "$re" ] && grep -qE "$re" <<<'https://github.com/MaliSec/temper.apps/.github/workflows/r.yml@refs/tags/2026.01.01' \
  && ! grep -qE "$re" <<<'https://github.com/MaliSec/temperXapps/.github/workflows/r.yml@refs/tags/2026.01.01' \
  && ! grep -qE "$re" <<<'https://github.com/MaliSec/temper.apps/.github/workflows/rXyml@refs/tags/2026.01.01' \
  && ok "the signer regex matches the repository and workflow literally" \
  || fail "the signer regex does not escape the repository or workflow: $re"
# The release phase, keyless: every image verified against this release's
# signer, the files named after the project, nothing named after Temper.
DT=$(date -u +%Y.%m.%d); AD="$TMP/apps-dist"; ACUT="$AD/registry-cut/$DT"; mkdir -p "$ACUT"
jq -n --arg d "$d0" '{scan_db: "x", scan_db_trivy: "x", gate_vulns: "true", images: [{name: "app",
  repository: "r.example/malisec/temper-apps/app", digest: $d, primary: true, line: "", vulns_grype: "g",
  vulns_trivy: "t", platforms: [{arch: "amd64", digest: $d}]}]}' > "$ACUT/images.json"
echo '{}' > "$ACUT/temper-apps-$DT.scans.json"; echo '{}' > "$ACUT/temper-apps-$DT.vex.json"
stubs; out=$(apps env -u CERT_IDENTITY_REGEXP PATH="$TMP/astub:$PATH" GITHUB_ACTIONS=true DATE="$DT" OUT_DIR="$AD" TEMPER_REV=unknown \
  "$TH/scripts/cut-registry.sh" finalize 2>&1) && rc=0 || rc=$?
m="$ACUT/temper-apps-$DT.manifest.yaml"
want="^https://github\\.com/MaliSec/temper-apps/\\.github/workflows/temper-apps-release-build\\.yml@refs/tags/${DT//./\\.}\$"
if [ "$rc" = 0 ] && [ -f "$m" ] && [ "$(head -1 "$m")" = "# Temper Apps release $DT (scripts/cut-registry.sh)" ] \
   && grep -qx 'image_repository: "r.example/malisec/temper-apps"' "$m" \
   && [ "$(sed -n 's/^signer_identity_regexp: "\(.*\)"$/\1/p' "$m" | sed 's/\\\\/\\/g')" = "$want" ] \
   && [ "$(signer_re)" = "$want" ] && grep -q -- '--certificate-github-workflow-repository MaliSec/temper-apps ' "$TMP/astub/cosign.log" \
   && grep -qx "tag r.example/malisec/temper-apps/app@$d0 $DT" "$TMP/astub/crane.log" \
   && [ -z "$(find "$AD" -name 'temper-2*')" ]; then
  ok "another project's release is verified against its own signer, tagged in its images, and named after it"
else fail "another project's finalize (exit $rc): $(tail -3 <<<"$out")"; fi
out=$(apps "$TH/scripts/image-line.sh" app 2>&1) && [ -z "$out" ] \
  && ! apps "$TH/scripts/image-line.sh" node >/dev/null 2>&1 \
  && ok "the scripts act on TEMPER_PROJECT_DIR's images, not Temper's" \
  || fail "image-line read Temper's images for another project: $out"
echo '{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}' > "$APPS/vex/CVE-1.json"
apps "$TH/scripts/vex-merge.sh" vex 2026.01.01 | jq -e '."@id" == "https://github.com/MaliSec/temper-apps/releases/tag/2026.01.01#vex"' >/dev/null \
  && ok "vex-merge names the project's own release" || fail "vex-merge named another repository's release"
avex() { jq -n --arg p "pkg:oci/app?repository_url=$1/app" '{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/v",
  author: "t", timestamp: "2026-01-01T00:00:00Z", version: 1, statements: [{vulnerability: {name: "CVE-1"},
  products: [{"@id": $p, subcomponents: [{"@id": "pkg:apk/wolfi/zlib@0-r0"}]}], status: "affected", action_statement: "x"}]}' > "$APPS/vex/CVE-1.json"; }
avex r.example/malisec/temper-apps; apps "$TH/scripts/vex-check.sh" >/dev/null 2>&1 && a=0 || a=1
avex ghcr.io/malisec/temper; apps "$TH/scripts/vex-check.sh" >/dev/null 2>&1 && b=0 || b=1
[ "$a$b" = 01 ] && ok "vex-check takes products in the project's images, not Temper's" \
  || fail "vex-check products for another project: own $a, Temper's $b (0 = accepted)"
rm -f "$APPS/vex/CVE-1.json"
out=$(env TEMPER_PROJECT_DIR="$APPS" ./scripts/vex-check.sh 2>&1) && grep -q '^vex: 0 file(s)' <<<"$out" \
  && ok "vex-check's default directories are the project's, wherever it is run from" \
  || fail "vex-check run from Temper's checkout for another project: $(tail -1 <<<"$out")"
for bad in 'repo=MaliSec' 'release_workflow=x.sh' 'name=Temper' 'owner=x' 'images=ghcr.io' 'images=ghcr.io/x/' \
           'images=ghcr.io/X' 'images=ghcr.io/x:1' 'images=https://ghcr.io/x'; do
  mkdir -p "$TMP/badproj"; { grep -v "^${bad%%=*}=" "$APPS/project.env"; echo "$bad"; } > "$TMP/badproj/project.env"
  out=$(env TEMPER_PROJECT_DIR="$TMP/badproj" ./scripts/image-line.sh app 2>&1) \
    && fail "project.env with '$bad' was accepted" \
    || { grep -q '^project.env: ' <<<"$out" && ok "project.env with '$bad' is refused" || fail "project.env with '$bad': $out"; }
done
mkdir -p "$TMP/nonl"; printf '%s' "$(cat "$APPS/project.env")" > "$TMP/nonl/project.env"
cp -r "$APPS/images" "$TMP/nonl/"
env TEMPER_PROJECT_DIR="$TMP/nonl" ./scripts/image-line.sh app >/dev/null 2>&1 \
  && ok "a project.env without a final newline keeps its last key" \
  || fail "a project.env without a final newline loses its last key"
# A relative --manifest is read from where the command runs, not from the
# project checkout the scripts change into.
mkdir -p "$TMP/mf"; printf 'images:\n  x:\n    repository: "r.example/o/x"\n    digest: "%s"\n' "$d0" > "$TMP/mf/m.yaml"
echo '{}' > "$TMP/mf/m.yaml.sigstore.json"
stubs; out=$(cd "$TMP/mf" && env TEMPER_PROJECT_DIR="$APPS" PATH="$TMP/astub:$PATH" TEMPER_REV=unknown \
  "$TH/scripts/verify-build.sh" "r.example/o/x@$d0" --manifest m.yaml 2>&1) \
  && grep -qF "listed in $TMP/mf/m.yaml: OK" <<<"$out" \
  && ok "a relative --manifest is read from the current directory" \
  || fail "a relative --manifest from another directory: $(tail -2 <<<"$out")"
mkdir -p "$TMP/noproj"
out=$(env TEMPER_PROJECT_DIR="$TMP/noproj" ./scripts/image-line.sh app 2>&1) \
  && fail "a project without project.env was accepted" \
  || { grep -qx "$TMP/noproj/project.env missing (see scripts/project.sh)" <<<"$out" \
       && ok "a project without project.env is refused" || fail "a project without project.env: $out"; }
# Pinned from another repository, an action runs from its own checkout of
# Temper and acts on the caller's: scripts by $GITHUB_ACTION_PATH, the
# project by $GITHUB_WORKSPACE (in a container job too) in every step that
# runs one. Inputs reach scripts through env, never expanded into the
# script text.
acts_bad=""
for a in .github/actions/*/action.yml; do
  grep -qE '(^|[^./_A-Za-z])\./scripts/' "$a" && acts_bad="$acts_bad $a:./scripts"
  grep -q 'scripts/' "$a" && ! grep -q 'GITHUB_ACTION_PATH/../../../scripts/' "$a" && acts_bad="$acts_bad $a:path"
  grep -q 'github\.workspace' "$a" && acts_bad="$acts_bad $a:github.workspace"
  steps=$(awk '/^    - name: /{n++} n{print n"\t"$0}' "$a")
  for n in $(cut -f1 <<<"$steps" | sort -un); do
    s=$(awk -F'\t' -v n="$n" '$1 == n {sub(/^[^\t]*\t/, ""); print}' <<<"$steps")
    grep -qE 'scripts/(build|cut-registry|project|image-line|lock-diff|vex-[a-z]+|scans-json)\.sh' <<<"$s" || continue
    grep -qx '        export TEMPER_PROJECT_DIR="$GITHUB_WORKSPACE"' <<<"$s" || acts_bad="$acts_bad $a:step$n"
  done
  awk '/^ *run: [|>]/{r=1; i=match($0,/[^ ]/); next} r && match($0,/[^ ]/) && RSTART<=i {r=0} /^ *run: /&&!/run: [|>]/{print} r{print}' "$a" | grep -q '\${{' && acts_bad="$acts_bad $a:interpolated"
done
[ -z "$acts_bad" ] && ok "the release actions run their own scripts on the caller's repository, inputs through env" \
  || fail "release actions:$acts_bad"
job build | grep -q 'uses: ./.github/actions/publish' && job release | grep -q 'uses: ./.github/actions/release' \
  && job packages | grep -q 'uses: ./.github/actions/packages' \
  && ok "Temper's own release runs the same actions" || fail "Temper's release does not use the shared actions"
# The publish phase pushes, and checks tags, only under IMAGE_REPO: no
# script names MaliSec's namespace itself.
ns=$(grep -niE 'malisec/' scripts/*.sh | grep -vE '^[^:]+:[0-9]+: *#' || true)
cr=scripts/cut-registry.sh
[ -z "$ns" ] && grep -qF 'ref="${IMAGE_REPO}/$(image_repo "$name")"' "$cr" \
  && grep -qF 'require_tag_absent "${IMAGE_REPO}/${repo}:${DATE}"' "$cr" \
  && ok "images publish only under IMAGE_REPO (project.env's images by default)" \
  || fail "a script names its own registry namespace or publishes outside IMAGE_REPO:"$'\n'"$ns"
# The scanners read Temper's empty config, never the project's files.
cr=scripts/cut-registry.sh pa=.github/actions/publish/action.yml
[ -z "$(grep -vE '^ *#' scripts/scanners.yaml)" ] \
  && [ "$(grep -cE '"\$(TRIVY|GRYPE|SYFT)" (image|db|"registry)' "$cr")" = 4 ] \
  && [ "$(grep -E '"\$(TRIVY|GRYPE|SYFT)" (image|db|"registry)' "$cr" | grep -cE -- '(-c|--config) "\$SCANNER_CONFIG"')" = 4 ] \
  && grep -qx 'SCANNER_CONFIG="$TEMPER_HOME/scripts/scanners.yaml"' "$cr" \
  && grep -A1 '"$TRIVY" image' "$cr" | grep -q -- '--ignorefile /dev/null' \
  && [ "$(grep -cE '^ +(trivy|grype) ' "$pa")" = 3 ] && [ "$(grep -E '^ +(trivy|grype) ' "$pa" | grep -cE -- '(-c|--config) "\$c"')" = 3 ] \
  && ok "trivy, grype and syft ignore config and ignore files in the project's checkout" \
  || fail "a scanner call can read the project's own config or ignore file"

echo "== supply chain: install-tools checksum posture =="
for var in APKO_SHA256_AMD64 APKO_SHA256_ARM64 MELANGE_SHA256_AMD64 MELANGE_SHA256_ARM64 COSIGN_SHA256_AMD64 \
           COSIGN_SHA256_ARM64 CRANE_SHA256_AMD64 CRANE_SHA256_ARM64 GRYPE_SHA256_AMD64 GRYPE_SHA256_ARM64 \
           SYFT_SHA256_AMD64 SYFT_SHA256_ARM64 TRIVY_SHA256 TRIVY_SHA256_ARM64; do
  grep -qE "^${var}=[0-9a-f]{64}" scripts/install-tools.sh \
    && ok "$var pinned (64-hex)" || fail "$var pinned checksum missing"
done
grep -v '^\s*#' scripts/install-tools.sh | grep -qE 'curl[^|]*\|\s*sh' \
  && fail "install-tools pipes curl to sh (unverified installer)" \
  || ok "no curl|sh installer in install-tools.sh"
# A release runs dozens of jobs that each download the tools; one refused
# download must not fail the release.
[ -z "$(grep -E '^\s*curl ' scripts/install-tools.sh | grep -v -- '--retry 5 --retry-all-errors')" ] \
  && ok "every tool download in install-tools.sh retries" \
  || fail "a tool download in install-tools.sh does not retry"
grep -E 'curl ' scripts/install-tools.sh | grep -q 'releases/download' \
  && ok "downloads come from pinned release URLs" \
  || fail "downloads are not release-pinned"
# Pins cover Linux on amd64 and arm64; anything else has no pin and is
# refused (checked by inspection: this host cannot be another platform).
grep -q 'require_linux' scripts/install-tools.sh && grep -q 'no pinned checksum; refusing to install' scripts/install-tools.sh \
  && ok "platform gate: Linux amd64 and arm64 only, anything else refused" \
  || fail "platform gate missing"

echo "== signing contract: keyless by default, no key material in the repo =="
grep -q 'certificate-identity-regexp' scripts/verify-build.sh scripts/cut-registry.sh \
  && ok "cut and verify check the signer's workflow identity" \
  || fail "cut/verify do not check a signer identity"
grep -q 'CERT_IDENTITY_REGEXP:-"${SIGNER_RE}@refs/tags/' scripts/verify-build.sh \
  && ok "verify-build defaults to this project's release workflow as signer" \
  || fail "verify-build default signer is not the release workflow"
if grep -v '^\s*#' scripts/verify-build.sh | grep -q 'cosign download attestation'; then
  fail "verify-build reads unverified attestations (cosign download attestation)"
else
  ok "verify-build reads only signature-verified attestations"
fi
grep -q '^/keys/$' .gitignore && ok ".gitignore excludes /keys/" || fail ".gitignore does not exclude /keys/"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  [ -z "$(git ls-files keys)" ] && ok "no key file is tracked under keys/" || fail "a file under keys/ is tracked"
fi

echo "== hygiene: no private material committed =="
# Tracked files plus untracked files git would add (not ignored). Outside a
# git work tree there is nothing to check, which is reported, not passed.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  committable=$( { git ls-files; git ls-files --others --exclude-standard; } )
  if grep -Eq '\.(key|pem|rsa)$|melange\.rsa$|cosign\.(key)$' <<<"$committable"; then
    fail "private key material tracked or committable: $(grep -E '\.(key|pem|rsa)$|cosign\.key$' <<<"$committable" | tr '\n' ' ')"
  else
    ok "no private key material tracked or committable"
  fi
  if grep -qE '^dist/|\.tar$|^packages/[^/]+/[^/]+\.apk$' <<<"$committable"; then
    fail "build artifacts tracked or committable"
  else
    ok "no build artifacts tracked or committable"
  fi
else
  echo "  SKIP: not a git work tree; the committed-file checks need git"
fi

echo "== smoke: python runtime image =="
# Needs the image in the local daemon:
#   ./scripts/build.sh --image python && docker load < dist/python.tar
# Skipped when the image is absent. SMOKE_NO_NETWORK=1 skips the TLS check.
DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
if command -v docker >/dev/null 2>&1 && docker image inspect "python:local-$DOCKER_ARCH" >/dev/null 2>&1; then
  pyline=$(./scripts/image-line.sh python)
  cid=$(docker create -e PYTHON_LINE="$pyline" --entrypoint "/usr/bin/python$pyline" "${PYTHON_IMAGE_REF:-python:local-$DOCKER_ARCH}" /smoke.py)
  docker cp tests/smoke-python.py "$cid":/smoke.py
  if docker start -a "$cid" >/dev/null 2>&1; then
    ok "python image smoke (interpreter, stdlib, TLS, nonroot, no shell/apk/pip)"
  else
    fail "python image smoke failed (see: docker start -a <cid>)"
  fi
  docker rm "$cid" >/dev/null 2>&1 || true
else
  echo "  skip: python image not built/loaded (build.sh --image python + docker load dist/python.tar)"
fi

echo "== smoke: -fips images =="
# Needs every -fips image in the local daemon (build.sh --image '*-fips*',
# docker load); with some but not all loaded, smoke-fips.sh fails.
fips_loaded=""
if command -v docker >/dev/null 2>&1; then
  for cfg in images/*-fips*/apko.yaml; do
    n=$(basename "$(dirname "$cfg")")
    docker image inspect "$n:local-$DOCKER_ARCH" >/dev/null 2>&1 && fips_loaded="$fips_loaded $n"
  done
fi
if [ -n "$fips_loaded" ]; then
  if smoke_err=$(tests/smoke-fips.sh "$DOCKER_ARCH" 2>&1 >/dev/null); then ok "-fips smoke, every line (gofips serves, non-approved refused, local TLS with resumption, no fallback)"
  else fail "-fips smoke failed (run: tests/smoke-fips.sh $DOCKER_ARCH): $(grep -m1 -E 'Error|not loaded' <<<"$smoke_err" || tail -1 <<<"$smoke_err")"; fi
else
  echo "  skip: no -fips image built/loaded"
fi

echo "---"

# Under pipefail, "producer | grep -q" reads an early match as a miss (the
# producer dies of SIGPIPE), so the policy gate must not test file lists
# that way.
if grep -nE '"\$filelist" *\|.*grep -q' scripts/check-policy.sh >/dev/null; then
  fail "check-policy.sh pipes the file list into grep -q (fails open under pipefail)"
else
  ok "check-policy.sh tests file lists without a SIGPIPE-prone pipe"
fi
# A shell listed first in a large image (its file list is far bigger than
# a pipe buffer): the gate must still see it.
mapfile -t big < <(printf 'bin/sh 0755\n'; seq -f 'zz/f%g 0644' 1 6000)
make_oci_tar "$POLICY/bigshell.tar" 65532 "${big[@]}"
expect_fail "a shell listed first in a large image is a policy violation" ./scripts/check-policy.sh "$POLICY/bigshell.tar"
make_oci_tar "$POLICY/layer2.tar" 65532 "usr/bin/app 0755" --layer "usr/bin/su 6755"
expect_fail "a setuid file in the second layer is a policy violation" ./scripts/check-policy.sh "$POLICY/layer2.tar"
make_oci_tar "$POLICY/hardlink.tar" 65532 "usr/bin/app 0755" "usr/bin/sh ln:usr/bin/app"
expect_fail "a shell name that is a hard link is a policy violation" ./scripts/check-policy.sh "$POLICY/hardlink.tar"
make_oci_tar "$POLICY/twolayer-ok.tar" 65532 "usr/bin/app 0755" --layer "etc/app.conf 0644"
expect_ok "a clean two-layer image passes" ./scripts/check-policy.sh "$POLICY/twolayer-ok.tar"

echo "== image references: verify-build's bare names =="
# vref <ref> [env...]: the reference verify-build's first cosign call checks.
vref() { local ref="$1"; shift; stubs
  env "$@" PATH="$TMP/astub:$PATH" TEMPER_REV=unknown ./scripts/verify-build.sh "$ref" --date 2026.01.01 >/dev/null 2>&1 || true
  awk '{print $NF; exit}' "$TMP/astub/cosign.log"; }
[ "$(vref static)" = "ghcr.io/malisec/temper/static@$d0" ] && ok "a bare name is looked up in project.env's images" \
  || fail "a bare name resolved to: $(vref static)"
[ "$(vref static IMAGE_REPO=reg.example/o)" = "reg.example/o/static@$d0" ] && ok "IMAGE_REPO overrides where a bare name is looked up" \
  || fail "IMAGE_REPO=reg.example/o resolved static to: $(vref static IMAGE_REPO=reg.example/o)"
[ "$(vref reg.example/other/name)" = "reg.example/other/name@$d0" ] && ok "a reference with a registry is used as given" \
  || fail "reg.example/other/name resolved to: $(vref reg.example/other/name)"

echo "== lockfile drift gate: copies the committed lockfiles before regenerating =="
# Checked on the workflow text: copying the lockfiles after the --lock run
# would compare each file to itself and never detect drift.
WF=.github/workflows/temper-build.yml
gate=$(awk '/name: Lockfile drift report$/{f=1;next} f&&/^      - name:/{exit} f' "$WF")
if echo "$gate" | awk '/cp "\$f" "lockfile-check\//{c=1} /build.sh --lock/{exit !c} END{if(!c) exit 1}'; then
  ok "drift gate snapshots the committed lockfiles before regenerating"
else
  fail "drift gate copies after regeneration (it would compare a lockfile with itself)"
fi
if echo "$gate" | grep -q 'jq.*"\$f" | jq.*> /tmp/a.json' && \
   echo "$gate" | grep -q 'jq.*"lockfile-check/.*> /tmp/b.json'; then
  ok "drift gate compares fresh output against the committed snapshot"
else
  fail "drift gate compares the wrong files"
fi
if echo "$gate" | grep 'build.sh --lock' | grep -q '|| true'; then
  fail "drift gate swallows a failed lock run"
else
  ok "drift gate fails when the lock run fails"
fi
echo "$gate" | awk '/drift=0/{d=1} d&&/cp "lockfile-check\/.*" "\$f"/{r=1} END{exit !r}' \
  && ok "drift report restores the committed lockfiles before the build" \
  || fail "drift report leaves regenerated lockfiles in place for the build"
echo "$gate" | grep -q 'for f in images/\*/apko\*.lock.json' \
  && ok "drift gate covers every image lockfile" \
  || fail "drift gate does not iterate over every image lockfile"
# The compare logic, mirroring the gate. Local packages (url under packages/)
# are stripped from both sides: the drift report is about Wolfi. A rebuilt
# local package that differs from its lock entry fails the image build
# itself (apko checks the control hash), and the recipes pin their build
# toolchain so a rebuild reproduces the locked package.
SIM="$TMP/sim"; mkdir -p "$SIM"
STRIP='[.contents.packages[] | select(((.url // "") | startswith("packages/") | not) and (.architecture == "x86_64"))]'
run_gate() { # committed fresh -> exit 0 iff they match (keyring + local packages stripped)
  echo "$1" | jq -S 'del(.contents.keyring)' | jq -S "$STRIP" > "$SIM/a.json"
  echo "$2" | jq -S 'del(.contents.keyring)' | jq -S "$STRIP" > "$SIM/b.json"
  diff -q "$SIM/a.json" "$SIM/b.json" >/dev/null
}
local_pkg='{"name":"local-pkg","version":"0.1.0-r0","architecture":"x86_64","url":"packages/x86_64/APKINDEX.tar.gz","checksum":"Q1AAA="}'
wolfi_pkg='{"name":"tzdata","version":"2026f-r0","architecture":"x86_64","url":"https://packages.wolfi.dev/os/x86_64/tzdata-2026f-r0.apk","checksum":"sha256:CCC"}'
lock_clean="{\"contents\":{\"packages\":[$local_pkg,$wolfi_pkg]}}"
lock_fresh="{\"contents\":{\"packages\":[{\"name\":\"local-pkg\",\"version\":\"0.1.0-r0\",\"url\":\"packages/x86_64/APKINDEX.tar.gz\",\"checksum\":\"Q1DIFFERENTKEY=\"},$wolfi_pkg]}}"
lock_drift="{\"contents\":{\"packages\":[$local_pkg,{\"name\":\"tzdata\",\"version\":\"2026g-r0\",\"url\":\"https://packages.wolfi.dev/os/x86_64/tzdata-2026g-r0.apk\",\"checksum\":\"sha256:DDD\"}]}}"
lock_local_drift="{\"contents\":{\"packages\":[{\"name\":\"local-pkg\",\"version\":\"0.2.0-r0\",\"url\":\"packages/x86_64/APKINDEX.tar.gz\",\"checksum\":\"Q1OTHER=\"},$wolfi_pkg]}}"
run_gate "$lock_clean" "$lock_clean" && ok "drift gate logic: clean lock passes" \
  || fail "drift gate logic: clean lock failed"
run_gate "$lock_clean" "$lock_fresh" && ok "drift gate logic: per-run local re-sign does not fail the gate" \
  || fail "drift gate logic: per-run local re-sign failed the gate (local checksums not stripped)"
if run_gate "$lock_clean" "$lock_drift"; then
  fail "drift gate logic: upstream package drift passed (gate did not detect it)"
else
  ok "drift gate logic: upstream package drift fails"
fi
run_gate "$lock_clean" "$lock_local_drift" && ok "drift gate scope: @local content drift is NOT detected (upstream-only gate, documented)" \
  || fail "drift gate scope: @local package change unexpectedly failed the gate (strip filter changed?)"

echo "== latest: forward-only date-tag ordering =="
nd() { printf '%s\n' "$@" | ./scripts/newest-date-tag.sh; }
[ "$(nd 2026.11.18 2026.11.19 latest sha256-x.sig)" = 2026.11.19 ] && ok "newest date tag ignores non-date tags" || fail "newest date tag picked a non-date tag"
[ "$(nd 2026.11.19 2026.11.19.1)" = 2026.11.19.1 ] && ok "a same-day .N release is newer than the plain date" || fail "same-day .N ordering wrong"
[ "$(nd 2026.11.19.2 2026.11.19.10)" = 2026.11.19.10 ] && ok "same-day suffixes order numerically" || fail "same-day suffixes order as strings"
[ "$(nd 2026.12.01 2026.11.30.9)" = 2026.12.01 ] && ok "a later date beats an earlier date's suffix" || fail "date ordering wrong"
[ -z "$(nd latest foo)" ] && ok "no date tag: nothing printed" || fail "non-date tags produced a result"
[ "$(nd 2026.11.19 2026.11.19.0 2026.11.19.01)" = 2026.11.19 ] && ok "a .0 or zero-padded suffix is not a date tag" || fail "a .0 or .01 suffix counted as a date tag"
grep -qF "'[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[1-9]'" .github/workflows/temper-release.yml \
  && ! grep -qE "\.\[0-9\]\+'" .github/workflows/temper-release.yml \
  && ok "the release trigger refuses a .0 or zero-padded suffix" || fail "temper-release.yml trigger accepts a .0 or .01 suffix"
grep -q 'newest-date-tag.sh' scripts/cut-registry.sh && grep -q 'crane tag "$pinned" latest' scripts/cut-registry.sh \
  && ok "the release moves latest only through the forward-only check" || fail "cut-registry does not gate latest"

echo "== scans-json.sh: the release's findings match the gate's counts =="
sj="$TMP/scans"; mkdir -p "$sj/scan"
cat > "$sj/records.json" <<'EOF'
{"scan_db": "grype DB built X", "scan_db_trivy": "trivy DB built Y", "images": [
 {"name": "app", "digest": "sha256:aa", "platforms": [
  {"arch": "amd64", "digest": "sha256:a1",
   "vulns_grype": "critical=0 high=0 medium=1 low=0 negligible=1 unknown=0 kev=0",
   "vulns_trivy": "critical=0 high=0 medium=1 low=0 unknown=0"}]}]}
EOF
cat > "$sj/scan/app.amd64.grype.json" <<'EOF'
{"descriptor": {"version": "0.1"}, "matches": [
 {"vulnerability": {"id": "CVE-1", "severity": "Medium", "fix": {"versions": ["1.1"], "state": "fixed"}},
  "artifact": {"name": "pkg", "version": "1.0", "type": "apk", "purl": "pkg:apk/wolfi/pkg@1.0"}},
 {"vulnerability": {"id": "CVE-2", "severity": "Negligible", "fix": {"versions": [], "state": ""}},
  "artifact": {"name": "pkg", "version": "1.0", "type": "apk", "purl": "pkg:apk/wolfi/pkg@1.0"}}]}
EOF
cat > "$sj/scan/app.amd64.trivy.json" <<'EOF'
{"Trivy": {"Version": "0.2"}, "Results": [{"Type": "wolfi", "Vulnerabilities": [
 {"VulnerabilityID": "CVE-1", "Severity": "MEDIUM", "PkgName": "pkg", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Status": "fixed"}]}]}
EOF
if out=$(./scripts/scans-json.sh "$sj/records.json" "$sj/scan" 2026.01.01 2>/dev/null) \
   && [ "$(jq -c '[.release, .scanners.grype.version, (.images.app.platforms.amd64.grype | map(.id + ":" + .severity + ":" + .fix_state)),
                   (.images.app.platforms.amd64.trivy | map(.id + ":" + (.fixed_in | join(","))))]' <<<"$out")" \
        = '["2026.01.01","0.1",["CVE-1:medium:fixed","CVE-2:negligible:unknown"],["CVE-1:1.1"]]' ]; then
  ok "scans-json normalizes both scanners' findings, negligible included"
else fail "scans-json output is not the expected normalized findings"; fi
sed -i 's/negligible=1/negligible=0/' "$sj/records.json"
expect_fail "scans-json refuses findings that do not match the gate's counts" \
  ./scripts/scans-json.sh "$sj/records.json" "$sj/scan" 2026.01.01
mkdir -p "$sj/vex" "$sj/images/app"
jq -n '{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/v", author: "t",
  timestamp: "2026-01-02T00:00:00Z", version: 1, statements: [
  {vulnerability: {name: "CVE-1"}, status: "fixed", status_notes: "fixed upstream",
   products: [{"@id": "pkg:oci/app?repository_url=ghcr.io/malisec/temper/app", subcomponents: [{"@id": "pkg:apk/wolfi/pkg@1.0"}]}]},
  {vulnerability: {name: "CVE-2"}, status: "not_affected", justification: "component_not_present", impact_statement: "x",
   products: [{"@id": "pkg:oci/app?repository_url=ghcr.io/malisec/temper/app", subcomponents: [{"@id": "pkg:apk/wolfi/pkg@9.9"}]}]}]}' \
  > "$sj/vex/CVE-1.json"
if ./scripts/vex-merge.sh "$sj/vex" 2026.01.01 > "$sj/vex.json" \
   && [ "$(jq -c '[."@context", (.statements | length), .statements[0].timestamp]' "$sj/vex.json")" \
        = '["https://openvex.dev/ns/v0.2.0",2,"2026-01-02T00:00:00Z"]' ]; then
  ok "vex-merge writes one OpenVEX document, each statement keeping its file's timestamp"
else fail "vex-merge output is not the merged OpenVEX document"; fi
sed -i 's/negligible=0/negligible=1/' "$sj/records.json"
if out=$(IMAGES_DIR="$sj/images" ./scripts/scans-json.sh "$sj/records.json" "$sj/scan" 2026.01.01 "$sj/vex.json" 2>/dev/null) \
   && [ "$(jq -c '[(.images.app.platforms.amd64.grype | map(.id + ":" + (.vex.status // "-"))),
                   (.images.app.platforms.amd64.trivy | map(.id + ":" + (.vex.status // "-")))]' <<<"$out")" \
        = '[["CVE-1:fixed","CVE-2:-"],["CVE-1:fixed"]]' ]; then
  ok "scans-json marks a finding with the statement for its vulnerability, image and exact package version"
else fail "scans-json applied VEX statements to the wrong findings"; fi
grep -q 'vex-check.sh" vex images' scripts/cut-registry.sh && grep -q 'vex_sha256' scripts/cut-registry.sh \
  && grep -q '${PROJECT_NAME}-${DATE}.vex.json' .github/actions/release/action.yml \
  && ok "the release checks the VEX statements, records the VEX file's sha256 and attaches it" \
  || fail "the release does not check, record or attach the VEX file"
grep -q 'negligible=$(gsev Negligible)' scripts/cut-registry.sh \
  && ok "the gate's grype counts include negligible findings" || fail "cut-registry's grype counts leave out negligible"

echo "== vex-check.sh: OpenVEX statements =="
./scripts/vex-check.sh >/dev/null 2>&1 && ok "the committed VEX statements are well formed" \
  || fail "vex/ has malformed statements (run: scripts/vex-check.sh)"
vx="$TMP/vex"; mkdir -p "$vx"
vexdoc() { # vexdoc <file> <statement json>
  jq -n --argjson s "$2" '{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/v",
    author: "t", timestamp: "2026-01-01T00:00:00Z", version: 1, statements: [$s]}' > "$vx/$1"
}
p='{"@id": "pkg:oci/node?repository_url=ghcr.io/malisec/temper/node", "subcomponents": [{"@id": "pkg:apk/wolfi/glibc-2.44@0-r0"}]}'
for c in \
  "unknown status|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"maybe\"}" \
  "not_affected without a justification|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"not_affected\", \"impact_statement\": \"x\"}" \
  "affected without an action statement|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"affected\"}" \
  "a statement for another vulnerability|CVE-2.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"affected\", \"action_statement\": \"x\"}" \
  "a product that is not a Temper image|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [{\"@id\": \"pkg:oci/nginx?repository_url=docker.io/library/nginx\"}], \"status\": \"affected\", \"action_statement\": \"x\"}" \
  "a product without a package version|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [{\"@id\": \"pkg:oci/node?repository_url=ghcr.io/malisec/temper/node\"}], \"status\": \"affected\", \"action_statement\": \"x\"}" \
  "a subcomponent purl with qualifiers|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [{\"@id\": \"pkg:oci/node?repository_url=ghcr.io/malisec/temper/node\", \"subcomponents\": [{\"@id\": \"pkg:apk/wolfi/glibc-2.44@0-r0?arch=x86_64\"}]}], \"status\": \"affected\", \"action_statement\": \"x\"}" \
  "statements that are not objects|CVE-1.json|\"CVE-1\"" \
  "fixed without evidence|CVE-1.json|{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"fixed\"}"; do
  label=${c%%|*} rest=${c#*|} file=${rest%%|*} stmt=${rest#*|}
  rm -f "$vx"/*.json; vexdoc "$file" "$stmt"
  expect_fail "vex-check refuses $label" ./scripts/vex-check.sh "$vx" images
done
rm -f "$vx"/*.json
vexdoc CVE-1.json "{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"affected\", \"action_statement\": \"x\"}"
if out=$(./scripts/vex-check.sh "$vx" images 2>&1) && grep -q 'stale: CVE-1 for node names glibc-2.44 0-r0' <<<"$out"; then
  ok "a statement for a package version no image ships is reported as stale, not failed"
else fail "vex-check did not report a stale statement, or failed on it"; fi
q='{"@id": "pkg:oci/node?repository_url=ghcr.io/malisec/temper/node", "subcomponents": [{"@id": "pkg:apk/wolfi/glibc-2.44@0-r1"}]}'
rm -f "$vx"/*.json
jq -n --argjson p "$p" --argjson q "$q" '{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/v",
  author: "t", timestamp: "2026-01-01T00:00:00Z", version: 1, statements: [
  {vulnerability: {name: "CVE-1"}, products: [$p], status: "affected", action_statement: "x"},
  {vulnerability: {name: "CVE-1"}, products: [$q], status: "affected", action_statement: "x"}]}' > "$vx/CVE-1.json"
./scripts/vex-check.sh "$vx" images >/dev/null 2>&1 \
  && ok "one product may have statements for two package versions (during a relock)" \
  || fail "vex-check rejects statements for two versions of a package on one product"
expect_fail "vex-check refuses a missing vex directory" ./scripts/vex-check.sh "$TMP/no-such-vex" images
rm -f "$vx"/*.json; mkdir -p "$vx/evidence"
vexdoc CVE-1.json "{\"vulnerability\": {\"name\": \"CVE-1\"}, \"products\": [$p], \"status\": \"affected\", \"action_statement\": \"x\"}"
evid() { # evid <label> <evidence json>
  echo "$2" > "$vx/evidence/CVE-1.json"
  expect_fail "vex-check refuses evidence with $1" ./scripts/vex-check.sh "$vx" images
}
sha=0123456789abcdef0123456789abcdef01234567
evid "another status than its statement" "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"$sha\"], \"check\": \"tests/vex/CVE-2026-16052.py\", \"lines\": {\"glibc-2.44\": {\"status\": \"fixed\", \"fix\": [\"$sha\"]}}}"
evid "a fixed line without fix commits" "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"$sha\"], \"check\": \"tests/vex/CVE-2026-16052.py\", \"lines\": {\"glibc-2.44\": {\"status\": \"fixed\", \"fix\": []}}}"
evid "a short commit" "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"0123456\"], \"check\": \"tests/vex/CVE-2026-16052.py\", \"lines\": {\"glibc-2.44\": {\"status\": \"affected\", \"fix\": []}}}"
evid "a missing check" "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"$sha\"], \"check\": \"tests/vex/none.py\", \"lines\": {\"glibc-2.44\": {\"status\": \"affected\", \"fix\": []}}}"
evid "a package no statement names" "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"$sha\"], \"check\": \"tests/vex/CVE-2026-16052.py\", \"lines\": {\"zlib\": {\"status\": \"affected\", \"fix\": []}}}"
echo "{\"vulnerability\": \"CVE-1\", \"issue\": \"gh-1\", \"upstream\": [\"$sha\"], \"check\": \"tests/vex/CVE-2026-16052.py\", \"lines\": {\"glibc-2.44\": {\"status\": \"affected\", \"fix\": []}}}" > "$vx/evidence/CVE-1.json"
./scripts/vex-check.sh "$vx" images >/dev/null 2>&1 && ok "vex-check accepts evidence that matches its statements" \
  || fail "vex-check refuses evidence that matches its statements"
rm -f "$vx/evidence/CVE-1.json"
grep -q 'scripts/vex-carry.sh' .github/workflows/temper-nightly.yml && grep -qF '"$message" images/ vex/' .github/workflows/temper-nightly.yml \
  && grep -q 'tests/vex-checks.sh' .github/workflows/temper-build.yml \
  && ok "the nightly relock carries VEX statements, and CI runs their checks" \
  || fail "the VEX carry or its checks are not wired into the nightly relock and CI"
# step <name>: one step of the nightly, up to the next.
NW=.github/workflows/temper-nightly.yml
step() { awk -v n="      - name: $1" '$0 == n {f=1; print; next} f && /^      - name: / {exit} f' "$NW"; }
step 'Carry VEX statements' | grep -q 'scripts/vex-carry.sh' && ! step 'Carry VEX statements' | grep -q '^        if:' \
  && step 'Changes to propose' | grep -qF 'git status --porcelain -- vex/' \
  && ok "the carry runs every night, and a carried statement alone opens the relock PR" \
  || fail "the carry runs only with package changes, or its result does not open the relock PR"
step 'Merge the relock' | grep -qF 'if ! gh pr merge' && step 'Merge the relock' | grep -q 'releasing main without it' \
  && ! step 'Tag main' | grep -q '^        if:' \
  && ok "a relock that cannot merge leaves tonight's release to main as it is" \
  || fail "a failed relock merge stops tonight's release"
step 'Open or update the relock PR' | grep -qF 'scripts/signed-commit.sh' \
  && step 'Open or update the relock PR' | grep -qF '.commit.verification.verified' \
  && ! step 'Open or update the relock PR' | grep -qE 'git (commit|push)' \
  && ok "the relock commit is made and signed by GitHub, and checked to be signed" \
  || fail "the relock commit is pushed from the runner, unsigned, and its merge is blocked"
step 'Check the Wolfi recipe mirror' | grep -qF 'repos/wolfi-dev/os/commits' && grep -qF 'cat /tmp/mirror.md' "$NW" \
  && ok "the nightly warns, in the relock PR too, when the Wolfi recipe mirror falls behind" \
  || fail "the nightly does not check the Wolfi recipe mirror"
bad=""
for ev in vex/evidence/*.json; do
  c=$(jq -r .check "$ev")
  python3 -I -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$c" 2>/dev/null || bad="$bad $c"
done
[ -z "$bad" ] && ok "every VEX check is valid Python" || fail "VEX checks that are not valid Python:$bad"

echo "== rollback-latest.sh: fail-closed interfaces =="
expect_fail "rollback without a tag fails" ./scripts/rollback-latest.sh
expect_fail "rollback with a malformed tag fails" ./scripts/rollback-latest.sh 2026.1.1
expect_fail "rollback with an unsigned manifest fails" env MANIFEST=tests/fixtures/no-such-manifest.yaml ./scripts/rollback-latest.sh 2026.01.01 --dry-run

echo "== version drift: docs and evidence agree with the lockfiles =="
# A README that states a version for a package in its image's lockfile must
# state the pinned one. Wolfi versions look like 1.2.3-r4.
readme_bad=0
for d in images/*/; do
  img=$(basename "$d"); lock="$d/apko.lock.json"; readme="$d/README.md"
  [ -f "$lock" ] && [ -f "$readme" ] || continue
  while read -r name ver; do
    # lines that name the package and carry a Wolfi version
    lines=$(grep -E "(^|[^A-Za-z0-9_-])\`?${name//+/\\+}\`?([^A-Za-z0-9_-]|$)" "$readme" || true)
    [ -n "$lines" ] || continue
    for v in $(printf '%s\n' "$lines" | grep -oE '[0-9][0-9A-Za-z._+~]*-r[0-9]+' | sort -u || true); do
      [ "$v" = "$ver" ] || echo "$img: README states $name $v, lockfile pins $ver"
    done
  done < <(jq -r '[.contents.packages[] | select(.architecture == "x86_64") | "\(.name) \(.version)"] | unique | .[]' "$lock")
done > "$TMP/readme-drift.txt"
if [ -s "$TMP/readme-drift.txt" ]; then
  sed 's/^/    /' "$TMP/readme-drift.txt" >&2; fail "image README versions disagree with the lockfiles"
else
  ok "image README versions agree with the lockfiles"
fi

# Each lockfile records the sha256 of the config it was resolved from. For
# configs without include:, that is the file's own hash. (Debug configs
# include their base config; apko computes those.)
ck_bad=""
for cfg in images/*/apko.yaml images/*/apko.debug.yaml; do
  [ -f "$cfg" ] || continue
  grep -q '^include:' "$cfg" && continue
  lock="${cfg%.yaml}.lock.json"
  want="sha256-$(openssl dgst -sha256 -binary "$cfg" | base64 -w0)"
  [ "$(jq -r .config.checksum "$lock")" = "$want" ] || ck_bad="$ck_bad $cfg"
done
[ -z "$ck_bad" ] && ok "lockfile config checksums match their configs" \
  || fail "lockfile config checksum is stale (run: make lock IMAGE=<name>):$ck_bad"
# A config with include: is not covered above: its lockfile must still pin
# every package its included config's lockfile pins, at the same version.
inc_bad=""
for cfg in images/*/apko.debug.yaml; do
  inc=$(sed -n 's/^include: *//p' "$cfg"); [ -n "$inc" ] || continue
  missing=$(jq -rn --slurpfile b "${inc%.yaml}.lock.json" --slurpfile d "${cfg%.yaml}.lock.json" '
    ($d[0].contents.packages | map("\(.name)=\(.version)/\(.architecture)")) as $have
    | [$b[0].contents.packages[] | "\(.name)=\(.version)/\(.architecture)" | select(. as $p | $have | index($p) | not)] | .[0] // empty')
  [ -z "$missing" ] || inc_bad="$inc_bad $cfg($missing)"
done
[ -z "$inc_bad" ] && ok "lockfiles of configs with include: pin every package of the config they include" \
  || fail "lockfile is stale against the config it includes (run: make lock IMAGE=<name>):$inc_bad"

# A -fips image is its base image plus the gofips packages and the
# environment that selects the provider (and, for node-fips, the guard):
# same packages, accounts and environment otherwise, and the same pinned
# versions.
fips_bad=""
for cfg in images/*-fips*/apko.yaml; do
  [ -f "$cfg" ] || continue
  # node-fips -> node, node-fips-24 -> node-24
  name=$(basename "$(dirname "$cfg")"); base="images/${name/-fips/}/apko.yaml"
  pkgs() { awk '/^  packages:/{f=1; next} f && /^    - /{print $2; next} f && !/^ *#/{f=0}' "$1" | grep -v '@local$' | sort; }
  block() { awk -v k="^$2:" '$0 ~ k {f=1; next} f && /^[a-z]/{f=0} f' "$1" | grep -vE '^ *#|^$|OPENSSL_CONF|GODEBUG|NODE_OPTIONS'; }
  [ "$(pkgs "$cfg")" = "$(pkgs "$base")" ] || fips_bad="$fips_bad $name:packages"
  [ "$(block "$cfg" accounts)" = "$(block "$base" accounts)" ] || fips_bad="$fips_bad $name:accounts"
  [ "$(block "$cfg" environment)" = "$(block "$base" environment)" ] || fips_bad="$fips_bad $name:environment"
  grep -q '^  OPENSSL_CONF: /etc/ssl/openssl-gofips.cnf$' "$cfg" || fips_bad="$fips_bad $name:OPENSSL_CONF"
  grep -q '^  GODEBUG: fips140=on$' "$cfg" || fips_bad="$fips_bad $name:GODEBUG"
  grep -q '^    - temper-gofips@local$' "$cfg" || fips_bad="$fips_bad $name:temper-gofips"
  if [[ "$name" == node-fips* ]]; then
    grep -q '^  NODE_OPTIONS: --require=/usr/lib/node-fips/guard.js --tls-cipher-list=' "$cfg" && grep -q '^    - temper-node-fips@local$' "$cfg" \
      || fips_bad="$fips_bad $name:node-guard"
    # OpenSSL 3 for native modules built against libssl.so.3: without it,
    # Prisma falls back to engines with their own TLS, outside gofips.
    grep -q '^    - openssl-3.6-libssl$' "$cfg" && grep -q '^    - openssl-3.6-libcrypto$' "$cfg" \
      || fips_bad="$fips_bad $name:openssl-3"
  fi
  if [[ "$name" == python-fips* ]]; then
    pyl=$(./scripts/image-line.sh "$name")
    [ -n "$pyl" ] && grep -q "^    - temper-python-$pyl-fips@local\$" "$cfg" && [ -d "packages/python-fips-$pyl" ] \
      && [ "$(grep -c -- '-fips@local$' "$cfg")" = 1 ] || fips_bad="$fips_bad $name:python-fips-package"
  fi
  pins() { jq -r '[.contents.packages[] | select((.url // "") | startswith("packages/") | not) | "\(.architecture) \(.name) \(.version)"] | sort | .[]' "$1"; }
  [ "$(pins "${cfg%.yaml}.lock.json")" = "$(pins "${base%.yaml}.lock.json")" ] || fips_bad="$fips_bad $name:lock"
done
[ -z "$fips_bad" ] && ok "-fips images match their base images (packages, accounts, environment, pins)" \
  || fail "-fips image differs from its base (relock: make lock IMAGE=<base image>):$fips_bad"

# The shipped gofips config must be the one the evidence was captured with.
strip_cnf() { grep -vE '^\s*(#|$)' "$1" | sed 's|GOFIPS_MODULE_PATH|/usr/lib/ossl-modules/gofips.so|'; }
[ "$(strip_cnf providers/gofips/openssl-gofips.cnf)" = "$(strip_cnf providers/gofips/testdata/node-integration/openssl-gofips.cnf)" ] \
  && ok "shipped openssl-gofips.cnf matches the tested config" \
  || fail "providers/gofips/openssl-gofips.cnf differs from testdata/node-integration/openssl-gofips.cnf"

# Version-line tags: the line each image gets, and how the release uses it.
lines_bad=""
for pair in node=26 node-fips=26 node-builder=26 node-debug=26 node-24=24 node-fips-24=24 node-builder-24=24 \
            python=3.14 python-fips=3.14 python-3.13=3.13 python-fips-3.13=3.13 go-builder=1.26 rust-builder=1.100 static= base-glibc= git=; do
  got=$(./scripts/image-line.sh "${pair%%=*}" 2>/dev/null || echo ERR)
  [ "$got" = "${pair#*=}" ] || lines_bad="$lines_bad ${pair%%=*}:$got"
done
[ -z "$lines_bad" ] && ok "image-line.sh derives each image's version line from its package stream" \
  || fail "image-line.sh lines:$lines_bad"
# Every image ships both architectures; a config build.sh would skip for
# one of them (an arch spelling it does not recognize, a missing entry) fails.
arch_bad=""
for cfg in images/*/apko.yaml; do
  got=$(ARCHS=x86_64,aarch64 bash -c 'source <(sed -n "/^cfg_archs()/,/^}/p" scripts/build.sh); cfg_archs "$1"' _ "$cfg")
  [ "$got" = "x86_64,aarch64" ] || arch_bad="$arch_bad $cfg:[$got]"
done
[ -z "$arch_bad" ] && ok "every image config builds for x86_64 and aarch64" \
  || fail "image configs not built for both architectures:$arch_bad"

readme_bad=""
for d in images/*/; do
  # An older line (images/node-24, repo file "node") is documented in its
  # repository's README.
  n=$(basename "$d"); l=$(./scripts/image-line.sh "$n")
  r=$(if [ -f "$d/repo" ]; then tr -d '[:space:]' < "$d/repo"; else echo "$n"; fi)
  if [ -n "$l" ]; then
    grep -qF "\`$r:$l\` follows the newest release on the $l line" "images/$r/README.md" || readme_bad="$readme_bad $n"
  else
    ! grep -q '^## Tags' "$d/README.md" || readme_bad="$readme_bad $n"
  fi
done
# A repo file names a primary image directory, and every line of a
# repository is distinct (two lines must never share a tag).
repo_bad=""
for f in images/*/repo; do
  [ -f "$f" ] || continue
  n=$(basename "$(dirname "$f")"); r=$(tr -d '[:space:]' < "$f")
  [ -f "images/$r/apko.yaml" ] && [ ! -f "images/$r/repo" ] || repo_bad="$repo_bad $n:no-primary-$r"
  [ -n "$(./scripts/image-line.sh "$n")" ] || repo_bad="$repo_bad $n:no-line"
done
dups=$(for d in images/*/; do n=$(basename "$d"); r=$(if [ -f "$d/repo" ]; then tr -d '[:space:]' < "$d/repo"; else echo "$n"; fi)
  echo "$r:$(./scripts/image-line.sh "$n")"; done | sort | uniq -d | tr '\n' ' ')
[ -z "$repo_bad$dups" ] && ok "older version lines publish to an existing primary repository, one tag per line" \
  || fail "image repo files:$repo_bad duplicate lines: $dups"
[ -z "$readme_bad" ] && ok "image README Tags sections name the image's current line" \
  || fail "README Tags section disagrees with scripts/image-line.sh:$readme_bad"
mkdir -p "$TMP/stub"
printf '#!/bin/sh\nexit 1\n' > "$TMP/stub/cosign"; cp "$TMP/stub/cosign" "$TMP/stub/crane"; chmod +x "$TMP/stub/"*
for t in latest 24; do
  out=$(PATH="$TMP/stub:$PATH" ./scripts/verify-build.sh node --date "$t" 2>&1 || true)
  grep -q 'is not a release tag' <<<"$out" && ok "verify-build refuses the floating tag '$t'" \
    || fail "verify-build accepted or mishandled the floating tag '$t': $out"
done
cr=scripts/cut-registry.sh
if grep -qF 'for t in $([ "$primary" = true ] && echo "$DATE") ${line:+"${line}-${DATE}"}' "$cr" \
   && grep -qF 'require_tag_absent "${IMAGE_REPO}/${repo}:${line}-${DATE}"' "$cr" \
   && grep -qF 'crane tag "${repo}@${digest}" "$line"' "$cr" \
   && grep -qF 'for t in $([ "$primary" = true ] && echo latest) ${line:+"$line"}' scripts/rollback-latest.sh; then
  ok "releases tag <line>-<date> immutably (the date and latest on the primary line only), advance <line> forward-only, and rollback moves it"
else
  fail "line tags: immutable <line>-<date>, forward-only <line>, rollback"
fi

# A release pushes by digest and adds the date tag only after verification,
# so a failed cut leaves no tag; an existing date tag stops it.
cr=scripts/cut-registry.sh
push_line=$(grep -n 'crane copy "$STAGE/$name@$digest" "${ref}@${digest}"' "$cr" | head -1 | cut -d: -f1 || true)
verify_line=$(grep -n '"$TEMPER_HOME/scripts/verify-build.sh" "$pinned"' "$cr" | head -1 | cut -d: -f1 || true)
tag_line=$(grep -n 'tag_once "$repo" "$digest" "$t"' "$cr" | head -1 | cut -d: -f1 || true)
if [ -n "$push_line" ] && [ -n "$verify_line" ] && [ -n "$tag_line" ] && [ "$verify_line" -lt "$tag_line" ] \
   && ! grep -qE 'crane (push|copy) [^|]*:\$\{DATE\}' "$cr" && [ "$(grep -c 'require_tag_absent "' "$cr")" -ge 2 ]; then
  ok "release copies each index by digest, tags the date only after verification, and refuses an existing date tag"
else
  fail "release ordering: push by digest, verify, then tag the date (and check the tag is absent)"
fi


echo "---"
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
