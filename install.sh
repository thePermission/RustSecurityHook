#!/usr/bin/env sh
# rsh - Rust Security Hook installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh
#
# Environment overrides:
#   RSH_VERSION       Specific tag to install (default: latest release)
#   RSH_INSTALL_DIR   Where to put the binary (default: $HOME/.local/bin)
#
# Supported platforms:
#   Linux  x86_64 (musl)   |  Linux  aarch64 (gnu)
#   macOS  x86_64          |  macOS  aarch64 (Apple Silicon)
set -eu

REPO="thePermission/RustSecurityHook"
BINARY="rsh"
INSTALL_DIR="${RSH_INSTALL_DIR:-${HOME}/.local/bin}"

info()  { printf '\033[1;34m[rsh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[rsh]\033[0m %s\n' "$*" >&2; }
fatal() { printf '\033[1;31m[rsh]\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fatal "required command '$1' not found"; }
need curl
need uname
need tar
need mkdir
need install

# --- OS / arch detection -------------------------------------------------
OS=$(uname -s)
ARCH=$(uname -m)

case "${OS}" in
    Linux*)   OS_TAG="linux"  ;;
    Darwin*)  OS_TAG="darwin" ;;
    *)        fatal "unsupported OS: ${OS}" ;;
esac

case "${ARCH}" in
    x86_64|amd64)    ARCH_TAG="x86_64"  ;;
    arm64|aarch64)   ARCH_TAG="aarch64" ;;
    *)               fatal "unsupported architecture: ${ARCH}" ;;
esac

case "${OS_TAG}-${ARCH_TAG}" in
    linux-x86_64)    TARGET="x86_64-unknown-linux-musl" ;;
    linux-aarch64)   TARGET="aarch64-unknown-linux-gnu" ;;
    darwin-x86_64)   TARGET="x86_64-apple-darwin"       ;;
    darwin-aarch64)  TARGET="aarch64-apple-darwin"      ;;
    *)               fatal "no prebuilt binary for ${OS_TAG}-${ARCH_TAG}" ;;
esac

# --- version selection ---------------------------------------------------
if [ -n "${RSH_VERSION:-}" ]; then
    VERSION="${RSH_VERSION}"
else
    # Resolve "latest" via the redirect from /releases/latest to /releases/tag/<v>.
    # Avoids hitting the GitHub API and its rate limit on anonymous calls.
    REDIRECT_URL=$(curl -sILo /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest")
    VERSION="${REDIRECT_URL##*/}"
    if [ -z "${VERSION}" ] || [ "${VERSION}" = "latest" ]; then
        fatal "could not resolve latest release of ${REPO} — does it have any releases yet?"
    fi
fi

# --- download + install --------------------------------------------------
ASSET="${BINARY}-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

info "Downloading ${BINARY} ${VERSION} for ${TARGET}..."
if ! curl -fsSL "${URL}" -o "${TMPDIR}/${ASSET}"; then
    fatal "download failed: ${URL}"
fi

info "Extracting..."
tar -xzf "${TMPDIR}/${ASSET}" -C "${TMPDIR}"
if [ ! -f "${TMPDIR}/${BINARY}" ]; then
    fatal "archive did not contain expected binary '${BINARY}'"
fi

mkdir -p "${INSTALL_DIR}"
install -m 0755 "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

info "Installed ${INSTALL_DIR}/${BINARY}"

# --- PATH hint -----------------------------------------------------------
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        warn "${INSTALL_DIR} is not on your PATH."
        warn "Add this to your shell rc:  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac

info "Verify with:  rsh --version"
info "Register as Claude Code hook (global):  rsh init -g"
info "Or per-project in current dir:           rsh init"
