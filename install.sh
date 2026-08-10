#!/usr/bin/env bash
#
# edgekit installer.
#
# Installs edgekit into an isolated virtualenv at /opt/edgekit and hands over to
# `edgekit setup`, which interviews you and provisions this server.
#
# Usage, from a checkout on the server:
#     sudo ./install.sh
#
# Or unattended, driven entirely by environment variables:
#     sudo EDGEKIT_PUBLIC_IP=1.2.3.4 EDGEKIT_CF_ZONE=example.com \
#          EDGEKIT_CF_TOKEN=... ./install.sh --non-interactive
#
# Sources, in the order they are tried:
#     EDGEKIT_SOURCE   local directory containing pyproject.toml (default: this script's dir)
#     EDGEKIT_REPO     git URL to clone
#     EDGEKIT_ARCHIVE  URL of a .tar.gz to download and unpack
#
set -Eeuo pipefail

PREFIX="${EDGEKIT_PREFIX:-/opt/edgekit}"
VENV="${PREFIX}/venv"
BIN="${VENV}/bin/edgekit"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR=""

# ------------------------------------------------------------------ output helpers

if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

step() { printf '%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_RESET"; }
ok()   { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
die()  { printf '%s✗ %s%s\n' "$C_RED" "$1" "$C_RESET" >&2; exit 1; }

cleanup() {
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf -- "$WORKDIR"
    fi
}
trap cleanup EXIT

on_error() {
    local line=$1
    printf '\n%s✗ Installation failed at line %s.%s\n' "$C_RED" "$line" "$C_RESET" >&2
    printf '  Nothing has been started. Re-run this script once the cause is fixed.\n' >&2
    printf '  Logs, if setup got that far: /var/log/edgekit/edgekit.log\n' >&2
}
trap 'on_error $LINENO' ERR

# ------------------------------------------------------------------ preflight

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Run this installer as root:  sudo $0 $*"
    fi
}

detect_os() {
    [ -r /etc/os-release ] || die "Cannot read /etc/os-release; unsupported system."
    # shellcheck disable=SC1091
    . /etc/os-release

    case " ${ID:-} ${ID_LIKE:-} " in
        *" debian "*|*" ubuntu "*|*" raspbian "*) ;;
        *) die "edgekit targets Debian and Ubuntu. Detected: ${PRETTY_NAME:-${ID:-unknown}}" ;;
    esac
    ok "${PRETTY_NAME:-${ID}} detected"
}

check_kernel_wireguard() {
    # Kernels since 5.6 carry WireGuard in-tree. Older ones need the DKMS module, which
    # apt pulls in — worth flagging early because it is the slow part of the install.
    local release major minor
    release="$(uname -r)"
    major="${release%%.*}"
    minor="${release#*.}"; minor="${minor%%.*}"
    if [ "${major:-0}" -lt 5 ] || { [ "${major:-0}" -eq 5 ] && [ "${minor:-0}" -lt 6 ]; }; then
        warn "Kernel $release predates in-tree WireGuard; the DKMS module will be built."
    fi
}

# ------------------------------------------------------------------ dependencies

install_dependencies() {
    step "Installing system dependencies"
    export DEBIAN_FRONTEND=noninteractive

    info "refreshing package index"
    apt-get update -qq

    local packages=(python3 python3-venv python3-pip ca-certificates curl gnupg iproute2 iptables)
    if [ -n "${EDGEKIT_REPO:-}" ]; then
        packages+=(git)
    fi

    info "installing: ${packages[*]}"
    apt-get install -y -qq --no-install-recommends "${packages[@]}"

    local python_version
    python_version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    case "$python_version" in
        3.1[0-9]|3.[2-9][0-9]) ok "Python $python_version" ;;
        *) die "Python 3.10 or newer is required; this system has $python_version." ;;
    esac
}

# ------------------------------------------------------------------ source

resolve_source() {
    step "Resolving edgekit source"

    if [ -n "${EDGEKIT_SOURCE:-}" ]; then
        [ -f "${EDGEKIT_SOURCE}/pyproject.toml" ] \
            || die "EDGEKIT_SOURCE=${EDGEKIT_SOURCE} has no pyproject.toml"
        SOURCE_DIR="${EDGEKIT_SOURCE}"
        ok "local directory ${SOURCE_DIR}"
        return
    fi

    if [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
        SOURCE_DIR="${SCRIPT_DIR}"
        ok "checkout at ${SOURCE_DIR}"
        return
    fi

    WORKDIR="$(mktemp -d)"
    if [ -n "${EDGEKIT_REPO:-}" ]; then
        info "cloning ${EDGEKIT_REPO}"
        git clone --depth 1 "${EDGEKIT_REPO}" "${WORKDIR}/src" >/dev/null 2>&1 \
            || die "Could not clone ${EDGEKIT_REPO}"
        SOURCE_DIR="${WORKDIR}/src"
        ok "cloned"
        return
    fi

    if [ -n "${EDGEKIT_ARCHIVE:-}" ]; then
        info "downloading ${EDGEKIT_ARCHIVE}"
        curl -fsSL "${EDGEKIT_ARCHIVE}" -o "${WORKDIR}/edgekit.tar.gz" \
            || die "Could not download ${EDGEKIT_ARCHIVE}"
        mkdir -p "${WORKDIR}/src"
        tar -xzf "${WORKDIR}/edgekit.tar.gz" -C "${WORKDIR}/src" --strip-components=1
        [ -f "${WORKDIR}/src/pyproject.toml" ] || die "Archive has no pyproject.toml at its root"
        SOURCE_DIR="${WORKDIR}/src"
        ok "unpacked"
        return
    fi

    die "No source found. Run this script from the edgekit checkout, or set EDGEKIT_SOURCE, EDGEKIT_REPO or EDGEKIT_ARCHIVE."
}

# ------------------------------------------------------------------ install

install_edgekit() {
    step "Installing edgekit into ${VENV}"

    mkdir -p "${PREFIX}"
    if [ ! -x "${VENV}/bin/python" ]; then
        info "creating virtualenv"
        python3 -m venv "${VENV}"
    else
        info "reusing existing virtualenv"
    fi

    info "upgrading pip"
    "${VENV}/bin/pip" install --quiet --upgrade pip setuptools wheel

    info "installing package and dependencies (this takes a minute)"
    "${VENV}/bin/pip" install --quiet "${SOURCE_DIR}"

    # A stable path on PATH means `edgekit` works for the operator and in the systemd unit.
    ln -sf "${BIN}" /usr/local/bin/edgekit

    ok "$("${BIN}" version)"
}

# ------------------------------------------------------------------ handover

run_setup() {
    step "Starting setup"
    printf '\n'
    # exec so signals and the exit code belong to setup, not to this wrapper.
    exec "${BIN}" setup "$@"
}

# ------------------------------------------------------------------ main

main() {
    printf '\n%s  edgekit installer%s\n' "$C_BOLD" "$C_RESET"
    printf '  %sWireGuard hub + Nginx Proxy Manager, on this server.%s\n\n' "$C_DIM" "$C_RESET"

    require_root "$@"
    detect_os
    check_kernel_wireguard
    install_dependencies
    resolve_source
    install_edgekit
    run_setup "$@"
}

main "$@"
