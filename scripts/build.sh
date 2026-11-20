#!/usr/bin/env bash
#
# build.sh: build Temper packages and images locally into OCI tars.
#
# Usage:
#   ./scripts/build.sh                 # keygen (if needed) + packages + images
#   ./scripts/build.sh --packages      # melange builds only
#   ./scripts/build.sh --images        # apko builds only (needs packages + lockfiles)
#   ./scripts/build.sh --lock          # regenerate lockfiles (all configs)
#   ./scripts/build.sh --index         # re-index and sign packages/<arch>/*.apk (CI gathers them per arch)
#   ./scripts/build.sh --lock --image node   # regenerate one image's lockfiles
#   ./scripts/build.sh --image static  # build a single image (accepts glob)
#   ./scripts/build.sh --arch x86_64   # restrict architectures (default: x86_64,aarch64)
#   ./scripts/build.sh --out-dir dist  # image tar output dir (default: dist/)
#   SUDO=1 ./scripts/build.sh          # run melange under sudo (for recipes
#                                      # whose workspace needs root to read)
#
# Prereqs: apko + melange on PATH (make install-tools), lockfiles committed
# (make lock), and a melange signing key (auto-generated if missing).
#
# Nothing is published; policy checks and publishing are in check-policy.sh
# and cut-registry.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${ARCHS:=x86_64,aarch64}"
: "${OUT_DIR:=dist}"
MODE="all"
IMAGE_FILTER="*"
SUDO_PREFIX=()
if [ "${SUDO:-0}" = "1" ] && command -v sudo >/dev/null 2>&1; then
  SUDO_PREFIX=(sudo -E env PATH="$PATH")
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --packages) MODE=packages ;;
    --images) MODE=images ;;
    --lock) MODE=lock ;;
    --index) MODE=index ;;
    --image) IMAGE_FILTER="$2"; shift ;;
    --arch) ARCHS="$2"; shift ;;
    --out-dir) OUT_DIR="$2"; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

command -v apko >/dev/null 2>&1 || { echo "apko not found — run: make install-tools" >&2; exit 1; }
# melange is only needed for local recipes (packages/*/melange.yaml); the
# base images use Wolfi packages alone.
shopt -s nullglob
RECIPES=(packages/*/melange.yaml)
shopt -u nullglob

# ensure_key: the melange key pair that signs packages/ and that @local
# images trust. Only package builds and @local images need it (or melange).
ensure_key() {
  command -v melange >/dev/null 2>&1 || { echo "melange not found — run: make install-tools" >&2; exit 1; }
  if [ ! -f melange.rsa ] || [ ! -f melange.rsa.pub ]; then
    echo "==> generating melange signing key"
    melange keygen
  fi
  [ -f melange.rsa.pub ] || { echo "melange.rsa.pub missing" >&2; exit 1; }
}

# Output goes to ./packages/, the '@local' repo the apko configs reference.
build_packages() {
  if [ ${#RECIPES[@]} -eq 0 ]; then
    echo "==> no package recipes under packages/: nothing to build"
    return 0
  fi
  ensure_key
  # bubblewrap (melange's default runner) cannot run unprivileged inside a
  # container, so those environments must pick a runner explicitly.
  RUNNER_ARGS=()
  if [ -z "${MELANGE_RUNNER:-}" ] && ! command -v bwrap >/dev/null 2>&1; then
    echo "bwrap not found on PATH — melange needs a runner (bwrap or docker);" >&2
    echo "set MELANGE_RUNNER=docker (or bwrap) to continue" >&2
    exit 1
  fi
  if [ -n "${MELANGE_RUNNER:-}" ]; then
    RUNNER_ARGS=(--runner "${MELANGE_RUNNER}")
  fi
  # melange's docker runner bind-mounts the workspace and the daemon resolves
  # that path on the host, so inside a container it must be host-visible.
  WORKSPACE_ARGS=()
  if [ -n "${MELANGE_WORKSPACE_DIR:-}" ]; then
    mkdir -p "${MELANGE_WORKSPACE_DIR}"
    WORKSPACE_ARGS=(--workspace-dir "${MELANGE_WORKSPACE_DIR}")
  fi
  for recipe in "${RECIPES[@]}"; do
    echo "==> melange build $recipe (${ARCHS})"
    # packages/<name>/source-dir names the repo directory the recipe builds from.
    SOURCE_ARGS=()
    srcfile="$(dirname "$recipe")/source-dir"
    [ -f "$srcfile" ] && SOURCE_ARGS=(--source-dir "$(tr -d '[:space:]' < "$srcfile")")
    # --git-commit is a constant: HEAD's sha would go into .PKGINFO and change
    # the package hash, and so the committed lockfile, on every commit. The
    # real commit is bound by the image provenance in cut-registry.sh.
    "${SUDO_PREFIX[@]}" melange build "$recipe" --arch "$ARCHS" --signing-key melange.rsa --git-commit unknown "${RUNNER_ARGS[@]}" "${WORKSPACE_ARGS[@]}" "${SOURCE_ARGS[@]}"
  done
  # docker-runner builds run the workspace as root; return the outputs to the
  # host user so nonroot apko/scan/publish runs can reuse them.
  if [ "$(id -u)" = 0 ] && [ -n "${HOST_UID:-}" ]; then
    echo "==> chowning build outputs to host uid ${HOST_UID}:${HOST_GID}"
    chown -R "${HOST_UID}:${HOST_GID}" packages 2>/dev/null || true
  fi
}

# A config's own archs: list restricts what it is built for; the result is
# its intersection with $ARCHS.
cfg_archs() {
  local want a out=()
  # apko accepts both spellings; compare in apk's (x86_64, aarch64).
  want=$(awk '/^archs:/{f=1; next} f && /^  - /{print $2; next} f{f=0}' "$1" \
    | sed 's/^amd64$/x86_64/; s/^arm64$/aarch64/' | paste -sd, -)
  [ -n "$want" ] || { echo "$ARCHS"; return; }
  for a in ${ARCHS//,/ }; do [[ ",$want," == *",$a,"* ]] && out+=("$a"); done
  (IFS=,; echo "${out[*]}")
}

lock_all() {
  # fips_twin <image>: node <-> node-fips, node-24 <-> node-fips-24.
  fips_twin() {
    local r t
    case "$1" in
      *-fips*) t="${1/-fips/}" ;;
      *) r="$1"; [ -f "images/$1/repo" ] && r=$(tr -d '[:space:]' < "images/$1/repo"); t="${r}-fips${1#"$r"}" ;;
    esac
    if [ -d "images/$t" ]; then printf '%s' "$t"; fi
  }
  # The configs to lock: those matching IMAGE_FILTER, and their -fips twins,
  # so an image and its -fips variant keep the same package versions (make
  # test checks this).
  local cfg name twin archs a
  local selected=()
  for cfg in images/*/apko.yaml images/*/apko.debug.yaml; do
    [ -f "$cfg" ] || continue
    name=$(basename "$(dirname "$cfg")")
    twin=$(fips_twin "$name")
    case "$name" in $IMAGE_FILTER) ;; *)
      [ -n "$twin" ] && case "$twin" in $IMAGE_FILTER) ;; *) continue ;; esac || continue ;;
    esac
    selected+=("$cfg")
  done
  [ ${#selected[@]} -gt 0 ] || { echo "no image config matches '$IMAGE_FILTER'" >&2; exit 1; }
  # Only @local images need the melange key (their keyring lists it).
  if grep -ql '@local' "${selected[@]}"; then ensure_key; fi
  for cfg in "${selected[@]}"; do
    archs=$(cfg_archs "$cfg"); [ -n "$archs" ] || continue
    if grep -q '@local' "$cfg"; then
      for a in ${archs//,/ }; do
        [ -f "packages/$a/APKINDEX.tar.gz" ] || { echo "$cfg uses @local packages: run ./scripts/build.sh --packages first" >&2; exit 1; }
      done
    fi
    echo "==> apko lock $cfg ($archs)"
    apko lock "$cfg" --arch "$archs"
  done
  echo "lockfiles regenerated — review with: git diff --stat images/"
}

# selected_local: does an image matching IMAGE_FILTER use the @local repo?
selected_local() {
  local cfg n
  for cfg in images/*/apko.yaml; do
    n=$(basename "$(dirname "$cfg")")
    case "$n" in $IMAGE_FILTER) grep -q '@local' "$cfg" && return 0 ;; esac
  done
  return 1
}

build_images() {
  if selected_local; then ensure_key; fi
  mkdir -p "$OUT_DIR"
  local built=0
  # GHCR links a package to the repository named here.
  SOURCE_ANNOTATION="org.opencontainers.image.source:https://github.com/MaliSec/temper"
  for cfg in images/*/apko.yaml; do
    name=$(basename "$(dirname "$cfg")")
    case "$name" in $IMAGE_FILTER) ;; *) continue ;; esac
    lock="images/$name/apko.lock.json"
    [ -f "$lock" ] || { echo "missing lockfile $lock — run: ./scripts/build.sh --lock" >&2; exit 1; }
    archs=$(cfg_archs "$cfg"); [ -n "$archs" ] || continue
    built=$((built + 1))
    echo "==> apko build $name ($archs)"
    apko build "$cfg" "$name:local" "$OUT_DIR/$name.tar" \
      --arch "$archs" --lockfile "$lock" --annotations "$SOURCE_ANNOTATION" --sbom-path "$(mkdir -p "$OUT_DIR/sbom/$name" && echo "$OUT_DIR/sbom/$name")"
    if [ -f "images/$name/apko.debug.yaml" ]; then
      dlock="images/$name/apko.debug.lock.json"
      [ -f "$dlock" ] || { echo "missing lockfile $dlock" >&2; exit 1; }
      # Its own archs: list if it has one, else the image's.
      darchs="$archs"
      if grep -q '^archs:' "images/$name/apko.debug.yaml"; then darchs=$(cfg_archs "images/$name/apko.debug.yaml"); fi
      [ -n "$darchs" ] || continue
      echo "==> apko build $name-debug ($darchs)"
      apko build "images/$name/apko.debug.yaml" "$name-debug:local" "$OUT_DIR/$name-debug.tar" \
        --arch "$darchs" --lockfile "$dlock" --annotations "$SOURCE_ANNOTATION" --sbom-path "$(mkdir -p "$OUT_DIR/sbom/$name-debug" && echo "$OUT_DIR/sbom/$name-debug")"
    fi
  done
  [ "$built" -gt 0 ] || { echo "no image config matches '$IMAGE_FILTER'" >&2; exit 1; }
}

# index_packages: (re)write each packages/<arch>/APKINDEX.tar.gz from the
# .apk files there, signed with this run's key. CI builds each
# architecture's packages on its own runner and indexes them together here.
index_packages() {
  ensure_key
  local d a n=0
  for d in packages/*/; do
    a=$(basename "$d")
    compgen -G "$d*.apk" >/dev/null || continue
    rm -f "$d/APKINDEX.tar.gz"
    melange index -a "$a" -o "$d/APKINDEX.tar.gz" --signing-key melange.rsa "$d"*.apk >/dev/null
    echo "==> indexed $(ls "$d"*.apk | wc -l) package(s) for $a"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || { echo "no packages to index under packages/" >&2; exit 1; }
}

case "$MODE" in
  index) index_packages ;;
  packages) build_packages ;;
  images) build_images ;;
  lock) lock_all ;;
  all) build_packages; build_images ;;
esac

echo "---"
echo "done. Outputs:"
# Guarded: under set -e, ls on an unmatched glob would abort the script.
if compgen -G "packages/x86_64/*.apk" >/dev/null; then
  ls packages/x86_64/*.apk 2>/dev/null | sed 's/^/  /'
fi
if compgen -G "$OUT_DIR/*.tar" >/dev/null; then
  ls "$OUT_DIR"/*.tar 2>/dev/null | sed 's/^/  /'
fi
echo "Next: ./scripts/check-policy.sh, ./scripts/verify-build.sh, ./scripts/cut-registry.sh"
