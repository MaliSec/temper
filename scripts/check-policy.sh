#!/usr/bin/env bash
#
# check-policy.sh: enforce the image hardening policy
# (policy/security-policy.md §1, §2) on locally built image tars.
#
# Any violation, or a tar that cannot be inspected, exits 1. Checks:
#   - run-as is the expected nonroot uid (65532, or images/<name>/policy-uid)
#   - no setuid/setgid bits on any non-directory entry
#   - non-debug images: no apk; no shell (sh, bash, busybox, ...) outside the
#     shell tier (base-shell and the builder images)
#   - every images/<name>/apko.yaml declares the expected run-as uid
#
# Usage:
#   ./scripts/check-policy.sh                 # inspect every dist/*.tar
#   ./scripts/check-policy.sh static          # single image (glob)
#   SKIP_UID_CHECK=1 ./scripts/check-policy.sh  # skip apko-config uid cross-check
set -euo pipefail
cd "$(dirname "$0")/.."

: "${OUT_DIR:=dist}"
: "${SKIP_UID_CHECK:=0}"
FILTER="${1:-*}"

fail() { echo "POLICY VIOLATION: $*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

# images/<name>/policy-uid overrides 65532 (one integer; justify it in the
# image's README).
expected_uid() {
  local name="$1" uidfile="images/$1/policy-uid"
  if [ -f "$uidfile" ]; then
    local u
    u=$(tr -d '[:space:]' < "$uidfile")
    case "$u" in ''|*[!0-9]*) fail "images/$name/policy-uid: not an integer uid: '$u'" ;; esac
    echo "$u"
  else
    echo "65532"
  fi
}

# Debug variants are exempt from the no-shell/no-apk checks (policy §2) but
# still checked for setuid and run-as.
is_debug() { case "$1" in *-debug) return 0 ;; *) return 1 ;; esac; }
# Images that ship a shell by design (policy §2).
# An older version line (images/node-builder-24) is in its repository's tier.
is_shell_tier() {
  local r="$1"
  [ -f "images/$1/repo" ] && r=$(tr -d '[:space:]' < "images/$1/repo")
  case "$r" in base-shell|base-glibc-dev|go-builder|node-builder) return 0 ;; *) return 1 ;; esac
}

# "mode name" per tar -tv line. A symlink line ends "name -> target": the
# name is the field before "->". A hard-link line ends "name link to
# target": both the link and its target are listed, with the link's mode.
entry_names() {
  awk '{
    n = $NF
    for (i = 1; i <= NF; i++) {
      if ($i == "->") { n = $(i-1); break }
      if ($i == "link" && $(i+1) == "to") { print $1, $(i-1); n = $NF; break }
    }
    print $1, n
  }'
}

check_tar() {
  local tar="$1" name
  name=$(basename "$tar" .tar)
  # FILTER may be a name glob ("static") or a tar path
  case "$tar" in $FILTER) ;; *) case "$name" in $FILTER) ;; *) return 0 ;; esac ;; esac
  CHECKED=$((CHECKED + 1))
  local debug=0; is_debug "$name" && debug=1
  local want_uid; want_uid=$(expected_uid "${name%-debug}")

  [ -s "$tar" ] || fail "$name: tar missing or empty: $tar"

  # index.json -> manifest -> config. OCI-layout tars store blobs at
  # blobs/sha256/<hex>; apko's docker-archive output uses "sha256:<hex>"
  # files and <hex>.tar.gz layers. Both are supported.
  # One manifest per platform (a multi-arch build lists each); every one is
  # checked.
  local entries config plat
  entries=$(tar -xOf "$tar" index.json 2>/dev/null | jq -r '.manifests[] | "\(.digest) \(.platform.architecture // "unknown")"' 2>/dev/null)
  [ -n "$entries" ] || fail "$name: cannot read manifest digests from $tar (not an OCI archive?)"
  while read -r config plat; do
    check_manifest "$tar" "$name" "$config" "$plat" "$debug" "$want_uid"
  done <<<"$entries"
}

check_manifest() {
  local tar="$1" name="$2" config="$3" plat="$4" debug="$5" want_uid="$6"
  blob() { # blob <tar> <digest> — print a blob's bytes under either layout
    local t="$1" dg="$2" hex="${2#sha256:}"
    tar -xOf "$t" "blobs/sha256/$hex" 2>/dev/null \
      || tar -xOf "$t" "sha256:$hex" 2>/dev/null
  }
  local manifest
  manifest=$(blob "$tar" "$config") \
    || fail "$name ($plat): cannot read manifest blob from $tar"
  local cfgdigest
  cfgdigest=$(printf '%s' "$manifest" | jq -r '.config.digest // empty' 2>/dev/null)
  [ -n "$cfgdigest" ] || fail "$name ($plat): manifest has no config digest"
  local cfgjson
  cfgjson=$(blob "$tar" "$cfgdigest") \
    || fail "$name ($plat): cannot read image config blob from $tar"
  local user
  user=$(printf '%s' "$cfgjson" | jq -r '.config.User // ""')
  [ "$user" = "$want_uid" ] || fail "$name ($plat): run-as is '$user', expected uid $want_uid (policy §1.1)"

  # apko produces one layer per arch, but every layer is inspected.
  local layer_digests layers
  layers=$(printf '%s' "$cfgjson" | jq -r '.rootfs.diff_ids[]')
  [ -n "$layers" ] || fail "$name ($plat): image has no layers"
  local filelist=""
  local d
  for d in $layers; do
    # diff_ids are uncompressed digests. OCI-layout tars keep the layer at
    # blobs/sha256/<diff_id>; docker-archive keeps it gzipped under the
    # manifest's (compressed) layer digest.
    if tar -xOf "$tar" "blobs/sha256/${d#sha256:}" 2>/dev/null | tar -tf - >/dev/null 2>&1; then
      filelist+=$(tar -xOf "$tar" "blobs/sha256/${d#sha256:}" 2>/dev/null | tar -tvf - 2>/dev/null | entry_names)$'\n'
    else
      # diff_id != compressed digest, so try every manifest layer
      local found=0 lp
      for lp in $(printf '%s' "$manifest" | jq -r '.layers[].digest' 2>/dev/null); do
        local hex="${lp#sha256:}"
        if tar -xOf "$tar" "blobs/sha256/$hex" 2>/dev/null | tar -tzf - >/dev/null 2>&1; then
          filelist+=$(tar -xOf "$tar" "blobs/sha256/$hex" 2>/dev/null | tar -tvzf - 2>/dev/null | entry_names)$'\n'
          found=1
        elif tar -xOf "$tar" "$hex.tar.gz" 2>/dev/null | tar -tzf - >/dev/null 2>&1; then
          filelist+=$(tar -xOf "$tar" "$hex.tar.gz" 2>/dev/null | tar -tvzf - 2>/dev/null | entry_names)$'\n'
          found=1
        fi
      done
      [ "$found" = 1 ] || fail "$name ($plat): layer ${d} not readable from $tar"
    fi
  done
  [ -n "$filelist" ] || fail "$name ($plat): rootfs listing empty"

  if awk '$1 !~ /^d/ && $1 ~ /[sStT]/ {f=1} END {exit !f}' <<<"$filelist"; then
    printf '%s\n' "$filelist" | awk '$1 !~ /^d/ && $1 ~ /[sStT]/' | sed 's/^/  /' >&2
    fail "$name ($plat): setuid/setgid file present (policy §1.2)"
  fi

  if [ "$debug" = 0 ]; then
    # Here-strings, not pipes: under pipefail, grep -q exiting on an early
    # match kills the writer with SIGPIPE and the match reads as a miss.
    if grep -qE '(^|/| )usr/(s)?bin/apk$' <<<"$filelist"; then
      fail "$name ($plat): apk (package manager) present in a runtime image (policy §1.5)"
    fi
    if ! is_shell_tier "$name" && grep -qE '(^|/| )(usr/)?s?bin/(sh|ash|bash|dash|zsh|busybox)$' <<<"$filelist"; then
      fail "$name ($plat): a shell is present outside the shell tier (policy §2): $(printf '%s\n' "$filelist" | grep -E '(^|/| )(usr/)?s?bin/(sh|ash|bash|dash|zsh|busybox)$' | head -3 | tr '\n' ' ')"
    fi
  fi

  echo "policy OK: $name/$plat (uid=$user, setuid=no, apk=no, shell-allowed=$([ "$debug" = 1 ] || is_shell_tier "$name" && echo yes || echo no))"
}

check_configs() {
  [ "$SKIP_UID_CHECK" = "1" ] && { echo "config uid check skipped (SKIP_UID_CHECK=1)"; return 0; }
  local cfg name
  for cfg in images/*/apko.yaml; do
    name=$(basename "$(dirname "$cfg")")
    local declared
    declared=$(awk '/^  run-as:/ {print $2; exit}' "$cfg")
    if [ -z "$declared" ]; then
      fail "$cfg: no run-as declared (policy §1.1)"
    fi
    local want; want=$(expected_uid "$name")
    [ "$declared" = "$want" ] || fail "$cfg: run-as $declared != expected $want (policy §1.1)"
  done
  echo "config run-as check OK: $(ls -d images/*/apko.yaml | wc -l) configs"
}

check_configs
CHECKED=0
# An explicit existing tar path is checked directly; otherwise scan $OUT_DIR.
if [ -f "$FILTER" ] && [[ "$FILTER" == *.tar ]]; then
  check_tar "$FILTER"
  echo "---"
  echo "policy check passed: 1 tar(s)"
  exit 0
fi
shopt -s nullglob
tars=("$OUT_DIR"/*.tar)
shopt -u nullglob
if [ ${#tars[@]} -eq 0 ]; then
  if [ "$FILTER" = "*" ]; then
    fail "no image tars under $OUT_DIR/ — run ./scripts/build.sh first (a policy check with nothing to check fails closed)"
  fi
  echo "no tars matched '$FILTER' under $OUT_DIR/ — nothing to check" >&2
  exit 1
fi
for tar in "${tars[@]}"; do
  check_tar "$tar"
done
# A filter that matches no tar checked nothing: that is not a pass.
[ "$CHECKED" -gt 0 ] || fail "no image tar under $OUT_DIR/ matches '$FILTER' (nothing was checked)"
echo "---"
echo "policy check passed: $CHECKED tar(s) under $OUT_DIR/"
