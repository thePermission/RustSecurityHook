#!/usr/bin/env sh
# rsh - Rust Security Hook installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh
#
# What it does:
#   1. Ensures a Rust toolchain (cargo) is available, installing rustup if not.
#   2. Runs `cargo install --git <repo>` to build and install the `rsh` binary
#      into ~/.cargo/bin.
#   3. Prints next-step instructions for `rsh init -g`.
#
# Supported platforms: Linux, macOS (anywhere rustup runs).
set -eu

REPO_URL="https://github.com/thePermission/RustSecurityHook.git"
BRANCH="main"

info()  { printf '\033[1;34m[rsh]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[rsh]\033[0m %s\n' "$*" >&2; }
fatal() { printf '\033[1;31m[rsh]\033[0m %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fatal "required command '$1' not found"
}

need curl
need sh

# 1. Cargo bereitstellen
if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "${HOME}/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "${HOME}/.cargo/env"
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    info "Rust toolchain not found, installing via rustup (minimal profile)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
    sh /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal
    rm -f /tmp/rustup-init.sh
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
fi

command -v cargo >/dev/null 2>&1 || fatal "cargo is still not available after rustup install"

# 2. rsh installieren
info "Installing rsh from ${REPO_URL} (branch: ${BRANCH})..."
cargo install --git "${REPO_URL}" --branch "${BRANCH}" --force rsh

# 3. PATH-Hinweis
CARGO_BIN="${CARGO_HOME:-${HOME}/.cargo}/bin"
case ":${PATH}:" in
    *":${CARGO_BIN}:"*) ;;
    *)
        warn "${CARGO_BIN} is not on your PATH."
        warn "Add this to your shell rc:  export PATH=\"${CARGO_BIN}:\$PATH\""
        ;;
esac

info "Done. Verify with:  rsh --help"
info "Register as Claude Code hook (global):  rsh init -g"
info "Or per-project in current dir:           rsh init"
