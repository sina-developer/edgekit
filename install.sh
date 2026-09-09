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
# When the network to PyPI is slow or blocked, point pip at a mirror:
#     sudo EDGEKIT_PIP_INDEX_URL=https://<mirror>/simple ./install.sh
#
# Other knobs:
#     EDGEKIT_APT_LOCK_WAIT   seconds to wait for apt/unattended-upgrades (default 900)
#     EDGEKIT_PIP_TIMEOUT     per-request pip timeout in seconds (default 60)
#     EDGEKIT_PIP_RETRIES     pip's own per-request retries (default 5)
#     EDGEKIT_PIP_ATTEMPTS    whole-command pip attempts (default 3)
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
#: How to tell the operator to re-run us: "$0" is just "bash" under `curl | bash`.
INSTALL_URL="https://cdn.jsdelivr.net/gh/sina-developer/edgekit@master/install.sh"
if [ -n "${SCRIPT_DIR}" ] && [ -f "${BASH_SOURCE[0]:-}" ]; then
    SELF="$0"
else
    SELF='bash -c "$(curl -fsSL '"${INSTALL_URL}"')"'
fi
#: Used when this script is piped via curl (no local checkout).
DEFAULT_REPO="${EDGEKIT_DEFAULT_REPO:-https://github.com/sina-developer/edgekit.git}"

#: How long to tolerate a busy apt (unattended-upgrades holds it for minutes on a fresh VPS).
APT_LOCK_WAIT="${EDGEKIT_APT_LOCK_WAIT:-900}"
APT_RETRIES="${EDGEKIT_APT_RETRIES:-5}"
#: pip's defaults (15s, 5 retries) give up too early on a congested link to PyPI.
PIP_TIMEOUT="${EDGEKIT_PIP_TIMEOUT:-60}"
PIP_RETRIES="${EDGEKIT_PIP_RETRIES:-5}"
PIP_ATTEMPTS="${EDGEKIT_PIP_ATTEMPTS:-3}"
INTERRUPTED=""

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
    local rc=$? line=$1
    # A Ctrl-C shows up here too; on_interrupt has already said its piece.
    if [ -n "$INTERRUPTED" ] || [ "$rc" -eq 130 ]; then
        return
    fi
    printf '\n%s✗ Installation failed at line %s.%s\n' "$C_RED" "$line" "$C_RESET" >&2
    printf '  Nothing has been started. Re-run this script once the cause is fixed.\n' >&2
    printf '  Logs, if setup got that far: /var/log/edgekit/edgekit.log\n' >&2
}
trap 'on_error $LINENO' ERR

on_interrupt() {
    INTERRUPTED=1
    printf '\n%s✗ Interrupted.%s Nothing has been started — re-run when ready.\n' \
        "$C_RED" "$C_RESET" >&2
    exit 130
}
trap on_interrupt INT

# ------------------------------------------------------------------ apt, patiently

#: A freshly booted VPS is usually mid-`unattended-upgrade`, which holds the dpkg lock for
#: minutes. Failing there is pure noise: the fix is to wait, so that is what we do.

apt_lock_holder() {
    local file pid
    if command -v fuser >/dev/null 2>&1; then
        for file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
                    /var/cache/apt/archives/lock /var/lib/apt/lists/lock; do
            [ -e "$file" ] || continue
            pid="$(fuser "$file" 2>/dev/null | tr -s ' \t' '\n' | grep -E '^[0-9]+$' | head -n1 || true)"
            if [ -n "$pid" ]; then
                printf '%s' "$pid"
                return 0
            fi
        done
        return 1
    fi
    # No psmisc: fall back to spotting the usual holders by name.
    if command -v pgrep >/dev/null 2>&1; then
        pid="$(pgrep -x 'apt|apt-get|aptitude|dpkg|unattended-upgrade' 2>/dev/null | head -n1 || true)"
        [ -n "$pid" ] || pid="$(pgrep -f 'unattended-upgrade' 2>/dev/null | head -n1 || true)"
        if [ -n "$pid" ]; then
            printf '%s' "$pid"
            return 0
        fi
    fi
    return 1
}

wait_for_apt() {
    local pid name waited=0
    pid="$(apt_lock_holder || true)"
    [ -n "$pid" ] || return 0

    name="$(cat "/proc/${pid}/comm" 2>/dev/null || echo process)"
    warn "apt is busy: ${name} (pid ${pid}) holds the dpkg lock"
    info "waiting up to $((APT_LOCK_WAIT / 60))m — unattended-upgrades finishes on its own"
    while [ "$waited" -lt "$APT_LOCK_WAIT" ]; do
        sleep 5
        waited=$((waited + 5))
        pid="$(apt_lock_holder || true)"
        if [ -z "$pid" ]; then
            ok "apt lock released after ${waited}s"
            return 0
        fi
        if [ $((waited % 60)) -eq 0 ]; then
            info "still waiting for ${name}… ${waited}s"
        fi
    done
    warn "apt still busy after ${waited}s — trying anyway"
}

apt_options() {
    APT_OPTS=(-o "Acquire::Retries=3")
    # DPkg::Lock::Timeout landed in apt 2.0 (Debian 11, Ubuntu 20.04); it closes the race
    # between wait_for_apt and the command itself.
    local version
    version="$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)"
    if [ -n "$version" ] && dpkg --compare-versions "$version" ge 2.0 2>/dev/null; then
        APT_OPTS+=(-o "DPkg::Lock::Timeout=${APT_LOCK_WAIT}")
    fi
}

#: apt-get, waiting out whoever holds the lock and retrying if one grabs it mid-run.
apt_get() {
    local attempt=1 rc log
    log="$(mktemp)"
    while :; do
        wait_for_apt
        set +e
        apt-get "${APT_OPTS[@]}" "$@" 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
        set -e
        if [ "$rc" -eq 0 ]; then
            rm -f "$log"
            return 0
        fi
        if [ "$attempt" -ge "$APT_RETRIES" ] \
            || ! grep -qiE 'could not get lock|frontend lock|another process using it|unable to lock' "$log"; then
            rm -f "$log"
            return "$rc"
        fi
        warn "apt was locked by another process (attempt ${attempt}/${APT_RETRIES}) — retrying in 15s"
        sleep 15
        attempt=$((attempt + 1))
    done
}

apt_failed() {
    die "apt-get $1 failed.

  If the message above mentions a dpkg lock, another package manager is still running.
  Watch it finish with:   ps aux | grep -E 'apt|dpkg|unattended'
  Then re-run this installer. To wait longer next time:
      sudo EDGEKIT_APT_LOCK_WAIT=1800 ${SELF}"
}

# ------------------------------------------------------------------ pip, patiently

pip_options() {
    #: pip's 15s default read timeout gives up on a congested link to PyPI mid-download.
    PIP_OPTS=(--disable-pip-version-check --timeout "$PIP_TIMEOUT" --retries "$PIP_RETRIES")
    if [ -n "${EDGEKIT_PIP_INDEX_URL:-}" ]; then
        PIP_OPTS+=(--index-url "${EDGEKIT_PIP_INDEX_URL}")
        # A mirror is often plain-HTTP or has its own CA; trust its host explicitly.
        local host="${EDGEKIT_PIP_INDEX_URL#*://}"
        PIP_OPTS+=(--trusted-host "${host%%/*}")
    fi
    if [ -n "${EDGEKIT_PIP_EXTRA_INDEX_URL:-}" ]; then
        PIP_OPTS+=(--extra-index-url "${EDGEKIT_PIP_EXTRA_INDEX_URL}")
    fi
}

pip_install() {
    local attempt=1 rc delay
    while :; do
        set +e
        "${VENV}/bin/pip" install "${PIP_OPTS[@]}" "$@"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        if [ "$attempt" -ge "$PIP_ATTEMPTS" ]; then
            return "$rc"
        fi
        delay=$((attempt * 10))
        warn "pip failed (attempt ${attempt}/${PIP_ATTEMPTS}) — retrying in ${delay}s"
        sleep "$delay"
        attempt=$((attempt + 1))
    done
}

pip_failed() {
    local index="${EDGEKIT_PIP_INDEX_URL:-https://pypi.org/simple}"
    die "pip could not install $1 from ${index}.

  Usually this is the network, not the package. Check reachability:
      curl -sS -m 20 -o /dev/null -w '%{http_code}\n' ${index}/
  If PyPI is slow or blocked from this server, re-run against a mirror, e.g.:
      sudo EDGEKIT_PIP_INDEX_URL=https://mirror.example.org/pypi/simple ${SELF}
  Or just give it longer:
      sudo EDGEKIT_PIP_TIMEOUT=120 EDGEKIT_PIP_ATTEMPTS=5 ${SELF}"
}

# ------------------------------------------------------------------ preflight

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Run this installer as root:  sudo ${SELF}"
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
    apt_options

    info "[1/3] refreshing package index"
    apt_get update -qq || apt_failed update
    ok "package index updated"

    local packages=(python3 python3-venv python3-pip ca-certificates curl gnupg iproute2 iptables)
    if [ -n "${EDGEKIT_REPO:-}" ]; then
        packages+=(git)
    fi

    info "[2/3] installing packages: ${packages[*]}"
    apt_get install -y --no-install-recommends "${packages[@]}" || apt_failed install
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
        curl -fsSL --connect-timeout 20 --max-time 600 \
            --retry 3 --retry-delay 5 --retry-connrefused \
            "${EDGEKIT_ARCHIVE}" -o "${WORKDIR}/edgekit.tar.gz" \
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
        apt_options
        apt_get install -y --no-install-recommends git || apt_failed install
        ok "git installed"
    fi

    local attempt=1
    while :; do
        info "cloning ${repo}"
        if git clone --depth 1 "${repo}" "${WORKDIR}/src"; then
            break
        fi
        rm -rf -- "${WORKDIR}/src"
        if [ "$attempt" -ge 3 ]; then
            die "Could not clone ${repo} after ${attempt} attempts.
  Check this server's connectivity to the repository host, or install from an archive:
      sudo EDGEKIT_ARCHIVE=<url-to-tar.gz> ${SELF}"
        fi
        warn "clone failed (attempt ${attempt}/3) — retrying in 10s"
        sleep 10
        attempt=$((attempt + 1))
    done
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

    pip_options
    info "[2/4] upgrading pip, setuptools, wheel"
    pip_install --upgrade pip setuptools wheel || pip_failed "pip, setuptools, wheel"
    ok "pip tooling upgraded"

    info "[3/4] installing edgekit and Python dependencies (this takes a minute)"
    pip_install "${SOURCE_DIR}" || pip_failed "edgekit and its dependencies"
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
