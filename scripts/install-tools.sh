#!/usr/bin/env bash
#
# install-tools.sh: install apko, melange, cosign, crane, grype, syft and
# trivy on the host. The containerized toolbox (`make toolbox`) avoids host
# installs and uses the same pinned versions.
#
# Usage:
#   ./scripts/install-tools.sh                 # install to ${INSTALL_DIR:-$HOME/.local/bin}
#   INSTALL_DIR=/usr/local/bin ./scripts/install-tools.sh
#   FORCE=1 ./scripts/install-tools.sh         # reinstall even if already present
#   TOOLS="apko cosign" ./scripts/install-tools.sh   # install a subset
#
# Each tool comes from its GitHub release at a pinned version and is
# sha256-checked against the pin below. When bumping a version, check the new
# sha256 against the checksum file published in that release.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
FORCE="${FORCE:-0}"
TOOLS="${TOOLS:-apko melange cosign crane grype syft trivy}"
mkdir -p "$INSTALL_DIR"

# Pins for linux/amd64 and linux/arm64, from each release's checksums file.
APKO_VERSION=1.2.37
MELANGE_VERSION=0.59.1
COSIGN_VERSION=3.1.3
CRANE_VERSION=0.21.9
GRYPE_VERSION=0.121.2
SYFT_VERSION=1.57.0
TRIVY_VERSION=0.76.2

APKO_SHA256_AMD64=9fa4ed893d0d87483a5f709fd5e2f1a1e6f93e40b35195949df2d9cf4f7093cc      # apko_1.2.37_linux_${goarch}.tar.gz
APKO_SHA256_ARM64=43e94fcda75df76e0b9fe78a98b2277ce4cc7eabe246e02df7c6f52c75b50f5d      # apko_1.2.37_linux_arm64.tar.gz
MELANGE_SHA256_AMD64=90f76f3e5fcb90ddc4c932ad352982bda98d58001d2bcccb982dd7fb2e608a1f   # melange_0.59.1_linux_${goarch}.tar.gz
MELANGE_SHA256_ARM64=aa5d221f92a248ba9aa490d1441c733417ad4c02f32fa9a13b8800acb42946f9   # melange_0.59.1_linux_arm64.tar.gz
COSIGN_SHA256_AMD64=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71    # cosign-linux-amd64 @ v3.1.3
COSIGN_SHA256_ARM64=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a    # cosign-linux-arm64 @ v3.1.3
CRANE_SHA256_AMD64=5c16d8ddb971cb1d5e6ed8b1e743da8224414eeba2c2762d8f1a61b2f095699e     # go-containerregistry_Linux_x86_64.tar.gz @ v0.21.9
CRANE_SHA256_ARM64=1f4c647b7bb260ab5435661df5b526cf59950ebf95201790db7183ac189cbcbd     # go-containerregistry_Linux_arm64.tar.gz @ v0.21.9
GRYPE_SHA256_AMD64=9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12     # grype_0.121.2_linux_${goarch}.tar.gz
GRYPE_SHA256_ARM64=d7d2e160255b0f087280feabf6f213cf4c45d475690f3f1fe5dc336eb1037bf0     # grype_0.121.2_linux_arm64.tar.gz
SYFT_SHA256_AMD64=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704     # syft_1.57.0_linux_${goarch}.tar.gz
SYFT_SHA256_ARM64=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb     # syft_1.57.0_linux_arm64.tar.gz
TRIVY_SHA256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf   # trivy_0.76.2_Linux-64bit.tar.gz
TRIVY_SHA256_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3   # trivy_0.76.2_Linux-ARM64.tar.gz

detect_os_arch() {
  case "$(uname -s)" in
    Linux) os="Linux" ;;
    Darwin) os="Darwin" ;;
    *) echo "unsupported OS: $(uname -s) — no pinned checksum; refusing to install" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "unsupported arch: $(uname -m) — no pinned checksum; refusing to install" >&2; exit 1 ;;
  esac
  # Release asset names (goarch: amd64/arm64; crane's unamearch:
  # x86_64/arm64) and the pins for this architecture.
  local A t
  case "$arch" in x86_64) A=AMD64; goarch=amd64; unamearch=x86_64 ;; arm64) A=ARM64; goarch=arm64; unamearch=arm64 ;; esac
  for t in APKO MELANGE COSIGN CRANE GRYPE SYFT; do
    eval "${t}_SHA256=\${${t}_SHA256_${A}}"
  done
  echo "detected: ${os}/${arch} → $INSTALL_DIR"
}

# already <tool> <pinned sha256>: installed by this script, into INSTALL_DIR,
# from the currently pinned release. A tool found elsewhere on PATH does not
# count: its checksum was never verified.
already() {
  local stamp="$INSTALL_DIR/.$1.sha256"
  [ "$FORCE" != "1" ] && [ -x "$INSTALL_DIR/$1" ] && [ -f "$stamp" ] \
    && [ "$(sed -n 1p "$stamp")" = "$2" ] \
    && [ "$(sed -n 2p "$stamp")" = "$(sha256sum "$INSTALL_DIR/$1" | cut -d' ' -f1)" ]
}

# record_pin <tool> <release sha256>: after a successful install, the pinned
# release checksum and the installed binary's own checksum.
record_pin() {
  printf '%s\n%s\n' "$2" "$(sha256sum "$INSTALL_DIR/$1" | cut -d' ' -f1)" > "$INSTALL_DIR/.$1.sha256"
}

TMPS=()
trap 'rm -rf "${TMPS[@]}"' EXIT
scratch() { local d; d=$(mktemp -d); TMPS+=("$d"); echo "$d"; }

verify_sha() { # file expected-sha256
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" != "$2" ]; then
    echo "CHECKSUM MISMATCH for $1: got $got, expected $2 — refusing to install" >&2
    exit 1
  fi
  echo "    checksum OK: ${got:0:16}…"
}

require_linux() { # <tool>
  if [ "$os" != "Linux" ]; then
    echo "$1: no checksum pin for ${os}/${arch} — failing closed; extend the pins in scripts/install-tools.sh first" >&2
    exit 1
  fi
}

install_apko() {
  if already apko "$APKO_SHA256"; then echo "apko: present ($("$INSTALL_DIR/apko" version | head -1)), skipping"; return; fi
  require_linux apko
  echo "apko: installing v${APKO_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/apko.tgz" \
    "https://github.com/chainguard-dev/apko/releases/download/v${APKO_VERSION}/apko_${APKO_VERSION}_linux_${goarch}.tar.gz"
  verify_sha "$tmp/apko.tgz" "$APKO_SHA256"
  tar -xzf "$tmp/apko.tgz" -C "$tmp"
  install -m 0755 "$tmp/apko_${APKO_VERSION}_linux_${goarch}/apko" "$INSTALL_DIR/apko"
  record_pin apko "$APKO_SHA256"
}

install_melange() {
  if already melange "$MELANGE_SHA256"; then echo "melange: present ($("$INSTALL_DIR/melange" version | head -1)), skipping"; return; fi
  require_linux melange
  echo "melange: installing v${MELANGE_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/melange.tgz" \
    "https://github.com/chainguard-dev/melange/releases/download/v${MELANGE_VERSION}/melange_${MELANGE_VERSION}_linux_${goarch}.tar.gz"
  verify_sha "$tmp/melange.tgz" "$MELANGE_SHA256"
  tar -xzf "$tmp/melange.tgz" -C "$tmp"
  install -m 0755 "$tmp/melange_${MELANGE_VERSION}_linux_${goarch}/melange" "$INSTALL_DIR/melange"
  record_pin melange "$MELANGE_SHA256"
}

install_cosign() {
  if already cosign "$COSIGN_SHA256"; then echo "cosign: present ($("$INSTALL_DIR/cosign" version 2>&1 | head -1)), skipping"; return; fi
  require_linux cosign
  echo "cosign: installing v${COSIGN_VERSION} (checksum-pinned release binary)"
  tmp="$(scratch)/cosign"
  curl -sSfL -o "$tmp" "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${goarch}"
  verify_sha "$tmp" "$COSIGN_SHA256"
  install -m 0755 "$tmp" "$INSTALL_DIR/cosign"
  record_pin cosign "$COSIGN_SHA256"
}

install_crane() {
  if already crane "$CRANE_SHA256"; then echo "crane: present ($("$INSTALL_DIR/crane" version | head -1)), skipping"; return; fi
  require_linux crane
  echo "crane: installing v${CRANE_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/crane.tgz" \
    "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${unamearch}.tar.gz"
  verify_sha "$tmp/crane.tgz" "$CRANE_SHA256"
  tar -xzf "$tmp/crane.tgz" -C "$tmp" crane
  install -m 0755 "$tmp/crane" "$INSTALL_DIR/crane"
  record_pin crane "$CRANE_SHA256"
}

install_grype() {
  if already grype "$GRYPE_SHA256"; then echo "grype: present ($("$INSTALL_DIR/grype" version 2>/dev/null | head -1)), skipping"; return; fi
  require_linux grype
  echo "grype: installing v${GRYPE_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/grype.tgz" \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${goarch}.tar.gz"
  verify_sha "$tmp/grype.tgz" "$GRYPE_SHA256"
  tar -xzf "$tmp/grype.tgz" -C "$tmp" grype
  install -m 0755 "$tmp/grype" "$INSTALL_DIR/grype"
  record_pin grype "$GRYPE_SHA256"
}

install_syft() {
  if already syft "$SYFT_SHA256"; then echo "syft: present ($("$INSTALL_DIR/syft" version 2>/dev/null | head -1)), skipping"; return; fi
  require_linux syft
  echo "syft: installing v${SYFT_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/syft.tgz" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${goarch}.tar.gz"
  verify_sha "$tmp/syft.tgz" "$SYFT_SHA256"
  tar -xzf "$tmp/syft.tgz" -C "$tmp" syft
  install -m 0755 "$tmp/syft" "$INSTALL_DIR/syft"
  record_pin syft "$SYFT_SHA256"
}

install_trivy() {
  require_linux trivy
  local tsha tarch
  case "$arch" in
    x86_64) tsha="$TRIVY_SHA256"; tarch=64bit;;
    arm64) tsha="$TRIVY_SHA256_ARM64"; tarch=ARM64;;
    *) echo "trivy: no checksum pin for ${os}/${arch} — failing closed" >&2; exit 1 ;;
  esac
  if already trivy "$tsha"; then echo "trivy: present ($("$INSTALL_DIR/trivy" --version 2>/dev/null | head -1)), skipping"; return; fi
  echo "trivy: installing v${TRIVY_VERSION} (checksum-pinned release tarball)"
  tmp=$(scratch)
  curl -sSfL -o "$tmp/trivy.tgz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tarch}.tar.gz"
  verify_sha "$tmp/trivy.tgz" "$tsha"
  tar -xzf "$tmp/trivy.tgz" -C "$tmp" trivy
  install -m 0755 "$tmp/trivy" "$INSTALL_DIR/trivy"
  record_pin trivy "$tsha"
}

main() {
  detect_os_arch
  for t in $TOOLS; do
    case "$t" in
      apko|melange|cosign|crane|grype|syft|trivy) "install_$t" ;;
      *) echo "unknown tool: $t" >&2; exit 1 ;;
    esac
  done
  echo "---"
  echo "Toolchain installed to: $INSTALL_DIR"
  echo "Add it to PATH if not already: export PATH=\"$INSTALL_DIR:\$PATH\""
}

main "$@"
