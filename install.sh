#!/usr/bin/env bash
#
# edgekit installer.
#
# Installs edgekit into an isolated virtualenv at /opt/edgekit and hands over to
# `edgekit setup`, which interviews you and provisions this server.
#
# Usage:
#     curl -fsSL https://cdn.jsdelivr.net/gh/sina-developer/edgekit@master/install.sh | sudo bash
#     sudo ./install.sh                          # from a local checkout
#     sudo edgekit update                        # later: fetch latest, keep settings
#
# Or unattended, driven entirely by environment variables:
#     sudo EDGEKIT_PUBLIC_IP=1.2.3.4 EDGEKIT_ZONE=example.com \
#          ./install.sh --non-interactive
#
# Sources, in the order they are tried:
#     EDGEKIT_SOURCE   local directory containing pyproject.toml (default: this script's dir)
#     EDGEKIT_REPO     git URL to clone (default: sina-developer/edgekit)
#     EDGEKIT_ARCHIVE  URL of a .tar.gz to download and unpack
#
set -Eeuo pipefail

PREFIX="${EDGEKIT_PREFIX:-/opt/edgekit}"
VENV="${PREFIX}/venv"
BIN="${VENV}/bin/edgekit"
# BASH_SOURCE is unset when the script is piped via `curl | bash`.
if [ -n "${BASH_SOURCE[0]:-}" ] && [ "${BASH_SOURCE[0]}" != "bash" ]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR=""
fi
WORKDIR=""
#: Used when this script is piped via curl (no local checkout).
DEFAULT_REPO="${EDGEKIT_DEFAULT_REPO:-https://github.com/sina-developer/edgekit.git}"

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

    info "[1/3] refreshing package index"
    apt-get update -qq
    ok "package index updated"

    local packages=(python3 python3-venv python3-pip ca-certificates curl gnupg iproute2 iptables)
    if [ -n "${EDGEKIT_REPO:-}" ]; then
        packages+=(git)
    fi

    info "[2/3] installing packages: ${packages[*]}"
    apt-get install -y --no-install-recommends "${packages[@]}"
    ok "system packages installed"

    info "[3/3] verifying Python"
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

    if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
        SOURCE_DIR="${SCRIPT_DIR}"
        ok "checkout at ${SOURCE_DIR}"
        return
    fi

    WORKDIR="$(mktemp -d)"

    # Archive wins only when explicitly requested without EDGEKIT_REPO.
    if [ -n "${EDGEKIT_ARCHIVE:-}" ] && [ -z "${EDGEKIT_REPO:-}" ]; then
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

    # curl | bash lands here: no local checkout, so clone the default (or EDGEKIT_REPO).
    local repo="${EDGEKIT_REPO:-$DEFAULT_REPO}"
    if ! command -v git >/dev/null 2>&1; then
        info "installing git"
        apt-get install -y --no-install-recommends git
        ok "git installed"
    fi
    info "cloning ${repo}"
    git clone --depth 1 "${repo}" "${WORKDIR}/src" \
        || die "Could not clone ${repo}"
    SOURCE_DIR="${WORKDIR}/src"
    ok "cloned"
}

# ------------------------------------------------------------------ install

install_edgekit() {
    step "Installing edgekit into ${VENV}"

    mkdir -p "${PREFIX}"
    if [ ! -x "${VENV}/bin/python" ]; then
        info "[1/4] creating virtualenv at ${VENV}"
        python3 -m venv "${VENV}"
        ok "virtualenv created"
    else
        info "[1/4] reusing existing virtualenv at ${VENV}"
        ok "virtualenv ready"
    fi

    info "[2/4] upgrading pip, setuptools, wheel"
    "${VENV}/bin/pip" install --upgrade pip setuptools wheel
    ok "pip tooling upgraded"

    info "[3/4] installing edgekit and Python dependencies (this takes a minute)"
    "${VENV}/bin/pip" install "${SOURCE_DIR}"
    ok "Python package installed"

    info "[4/4] linking edgekit onto PATH"
    # A stable path on PATH means `edgekit` works for the operator and in the systemd unit.
    ln -sf "${BIN}" /usr/local/bin/edgekit
    ok "$("${BIN}" version) → /usr/local/bin/edgekit"
}

# ------------------------------------------------------------------ handover

attach_controlling_tty() {
    # `curl | sudo bash` feeds this script on stdin. Once that pipe is consumed,
    # the first setup prompt (public IP) gets EOF and Click prints "Aborted".
    # Reopen the controlling terminal so the interview can wait for the operator.
    # Skip when /dev/tty is absent (cloud-init, CI) so --non-interactive still works.
    if [ -t 0 ]; then
        return 0
    fi
    if [ -r /dev/tty ]; then
        exec </dev/tty
    fi
}

run_setup() {
    step "Starting setup"
    printf '\n'
    attach_controlling_tty
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
