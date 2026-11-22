#!/usr/bin/env bash
#
# trivy-regression.sh: check that the release gates on both Trivy and Grype.
#
# Inspects cut-registry.sh, install-tools.sh and the workflows: both scanners
# run and write JSON records, the gate counts criticals from both, the trivy
# DB is refreshed and pinned, failures propagate, and trivy is
# checksum-pinned. No registry, network or keys.
#
# Usage: ./tests/trivy-regression.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1" >&2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== gate: both scanners run, machine-readable records, union criticals =="
CR=scripts/cut-registry.sh
grep -q '"\$TRIVY" image --config "\$SCANNER_CONFIG" --ignorefile /dev/null --insecure --platform "linux/\$arch"' "$CR" \
  && ok "cut scans every platform with trivy (staged index, --platform)" \
  || fail "cut does not invoke trivy per platform"
grep -q '"\$GRYPE" "registry:\$staged" -c "\$SCANNER_CONFIG" --platform "linux/\$arch" -o json' "$CR" \
  && ok "cut scans every platform with grype" \
  || fail "grype scan missing from the cut"
grep -q 'base="\$CUT_DIR/scan/\${name}\.\${arch}"' "$CR" && grep -q '"\$base.trivy.json"' "$CR" \
  && ok "trivy writes a per-platform machine-readable record (scan/<name>.<arch>.trivy.json)" \
  || fail "trivy record path missing"
grep -q '\-\-format json' "$CR" \
  && ok "trivy output is machine-readable (JSON)" \
  || fail "trivy output not pinned to JSON"
grep -q '"\$base.grype.json"' "$CR" \
  && ok "grype keeps a per-platform JSON record" \
  || fail "grype record path missing"
grep -qE 'crit_total=\$\(\( *crit_total \+ tcrit \+ crit *\)\)' "$CR" \
  && ok "gate counts the UNION of both scanners' criticals, across every platform" \
  || fail "gate is not the union of trivy+grype criticals"
grep -q 'unscannable is not a pass' "$CR" \
  && ok "unscannable tar fails the cut (fail-closed, no silent skip)" \
  || fail "fail-closed scan contract wording missing"
grep -q 'TRIVY_DB_NOTE' "$CR" \
  && ok "trivy DB freshness recorded (never silently skipped)" \
  || fail "trivy DB freshness note missing"
grep -q 'skip-db-update' "$CR" \
  && ok "cut pins the trivy DB to the refreshed runner cache (no live network mid-release)" \
  || fail "trivy DB handling not pinned"

trivy_line=$(grep -n '"\$TRIVY" image ' "$CR" | head -1 | cut -d: -f1)
grype_line=$(grep -n '"\$GRYPE" "registry:' "$CR" | head -1 | cut -d: -f1)
gate_line=$(grep -n 'GATE: \$name has' "$CR" | head -1 | cut -d: -f1)
if [ -n "$trivy_line" ] && [ -n "$grype_line" ] && [ -n "$gate_line" ] \
   && [ "$trivy_line" -lt "$grype_line" ] && [ "$grype_line" -lt "$gate_line" ]; then
  ok "gate fires after both scanners have recorded (trivy -> grype -> gate)"
else
  fail "gate/scanner order wrong (trivy=$trivy_line grype=$grype_line gate=$gate_line)"
fi
copy_line=$(grep -n 'crane copy "\$STAGE/\$name@\$digest" "\${ref}@\${digest}"' "$CR" | head -1 | cut -d: -f1)
if [ -n "$copy_line" ] && [ -n "$gate_line" ] && [ "$gate_line" -lt "$copy_line" ] && grep -q 'start_staging' "$CR"; then
  ok "scans and the gate run on the local staging copy, before anything reaches the registry"
else
  fail "publish order: the gate must run before the copy to the registry (gate=$gate_line copy=$copy_line)"
fi

echo "== gate: the cut's severity counters on known records =="
# The real counting functions from cut-registry.sh, on records with known
# counts: a filter that miscounts criticals would let the gate pass.
eval "$(grep -E '^ *tsev\(\) \{' "$CR")"
eval "$(grep -E '^ *gsev\(\) \{' "$CR")"
base="$TMP/fixture"
jq -n '{Results: [{Vulnerabilities: [{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "HIGH"}, {}]}, {Vulnerabilities: [{Severity: "CRITICAL"}]}]}' > "$base.trivy.json"
jq -n '{matches: [{vulnerability: {severity: "Critical"}}, {vulnerability: {severity: "Low"}}, {vulnerability: {}}]}' > "$base.grype.json"
got="trivy crit=$(tsev CRITICAL) high=$(tsev HIGH) unknown=$(tsev UNKNOWN); grype crit=$(gsev Critical) low=$(gsev Low) unknown=$(gsev Unknown)"
[ "$got" = "trivy crit=2 high=2 unknown=1; grype crit=1 low=1 unknown=1" ] \
  && ok "the cut counts criticals correctly in trivy and grype records" \
  || fail "severity counters miscount: $got"
eval "$(grep -E '^ *gkev\(\) \{' "$CR")"
jq -n '{matches: [{vulnerability: {severity: "Low", knownExploited: [{cve: "CVE-2021-44228"}]}},
                  {vulnerability: {severity: "High", knownExploited: []}}, {vulnerability: {severity: "Medium"}}]}' > "$base.grype.json"
[ "$(gkev)" = "1" ] && ok "the cut counts known-exploited findings at any severity" || fail "KEV counter miscounts: $(gkev)"
grep -qE 'crit_total" != "0" \] \|\| \[ "\$kev_total" != "0"' "$CR" \
  && ok "gate fails on a known-exploited finding as well as on a critical" \
  || fail "gate ignores known-exploited findings"
jq -n '{Results: []}' > "$base.trivy.json"; jq -n '{}' > "$base.grype.json"
[ "$(tsev CRITICAL)$(gsev Critical)$(gkev)" = "000" ] && ok "empty records count zero" || fail "empty records miscount"

echo "== manifest: per-scanner vuln lines =="
grep -q 'vulns_trivy' "$CR" \
  && ok "manifest carries a vulns_trivy line per image" \
  || fail "manifest missing vulns_trivy"
grep -q 'scan_db_trivy' "$CR" \
  && ok "manifest header carries the trivy DB note" \
  || fail "manifest header missing trivy DB note"

echo "== workflow: trivy invoked, failures propagate =="
WF=.github/workflows/temper-build.yml
grep -q 'scripts/install-tools.sh' "$WF" \
  && ok "workflow installs the toolchain (trivy included)" \
  || fail "workflow does not install the toolchain"
RWF=.github/actions/publish/action.yml
if [ ! -f "$RWF" ]; then
  fail "$RWF missing: release-job checks not run"
else
grep -q -- '--download-db-only' "$RWF" \
  && ok "workflow refreshes the trivy DB before the release job" \
  || fail "workflow does not refresh the trivy DB"
grep -q 'scripts/cut-registry.sh" publish' "$RWF" \
  && ok "workflow runs the cut (which gates on trivy+grype)" \
  || fail "workflow does not run the cut"
grep -q 'scan/\${name}\.trivy\.json\|dist/registry-cut/\*\*' "$RWF" \
  && ok "workflow uploads the scan evidence (trivy records included)" \
  || fail "workflow does not upload scan evidence"
grep -q 'if-no-files-found: error' "$RWF" \
  && ok "evidence upload fails closed (if-no-files-found: error)" \
  || fail "evidence upload tolerates missing files"
rel_step=$(sed -n '/Scan -> publish/,/cut-registry.sh/p' "$RWF")
if echo "$rel_step" | grep -q '|| true\|continue-on-error'; then
  fail "release step swallows failures"
else
  ok "release step propagates failures (no swallow)"
fi
fi

echo "== install-tools: trivy checksum-pinned =="
IT=scripts/install-tools.sh
grep -qE '^TRIVY_VERSION=[0-9.]+' "$IT" \
  && ok "TRIVY_VERSION pinned" \
  || fail "TRIVY_VERSION missing"
grep -qE '^TRIVY_SHA256=[0-9a-f]{64}' "$IT" \
  && ok "TRIVY_SHA256 pinned (64-hex)" \
  || fail "TRIVY_SHA256 missing"
grep -qE '^TRIVY_SHA256_ARM64=[0-9a-f]{64}' "$IT" \
  && ok "TRIVY_SHA256_ARM64 pinned (64-hex)" \
  || fail "TRIVY_SHA256_ARM64 missing"
grep -q 'install_trivy' "$IT" \
  && ok "install_trivy wired into main()" \
  || fail "install_trivy not called"
grep -A1 -E 'curl ' "$IT" | grep -q 'aquasecurity/trivy/releases/download' \
  && ok "trivy downloads from its pinned release URL" \
  || fail "trivy download not release-pinned"

echo "== scope: no unimplemented scanner claims in the release path =="
scanner_refs=$(grep -rhoE '\b(clair|dockle|osv-scanner|snyk|prisma|qualys|xray|scout)\b' \
  scripts/cut-registry.sh Makefile 2>/dev/null | sort -u || true)
[ -z "$scanner_refs" ] \
  && ok "release path names no scanner beyond trivy+grype" \
  || fail "unexpected scanner references: $scanner_refs"
grep -q 'Trivy and Grype' policy/security-policy.md \
  && ok "policy states the Trivy + Grype scanning requirement (§3.5)" \
  || fail "policy scanning requirement not found"

echo "---"
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
