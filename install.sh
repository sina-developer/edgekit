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
#     EDGEKIT_PYTHON          interpreter to build the venv from (default python3)
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
#: The interpreter the venv is built from. Worth overriding when the system Python is newer
#: than the compiled dependencies have wheels for.
PYTHON_BIN="${EDGEKIT_PYTHON:-python3}"
#: Last pip run's output, kept so a failure can be classified rather than guessed at.
PIP_LOG=""
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
    if [ -n "$PIP_LOG" ] && [ -f "$PIP_LOG" ]; then
        rm -f -- "$PIP_LOG"
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
    [ -n "$PIP_LOG" ] || PIP_LOG="$(mktemp)"
    while :; do
        set +e
        "${VENV}/bin/pip" install "${PIP_OPTS[@]}" "$@" 2>&1 | tee "$PIP_LOG"
        rc=${PIPESTATUS[0]}
        set -e
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        # A resolution failure is deterministic: the index either has a usable build for
        # this interpreter or it does not. Retrying just spends minutes reaching the same
        # answer, so hand it straight to the recovery path.
        if pip_resolution_failed; then
            return "$rc"
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

#: True when pip could not find a usable build, as opposed to failing to reach the index.
pip_resolution_failed() {
    [ -n "$PIP_LOG" ] && [ -f "$PIP_LOG" ] || return 1
    grep -qiE 'resolutionimpossible|no matching distribution|no matching distributions' \
        "$PIP_LOG"
}

#: The package names pip named as unavailable, on one line.
pip_missing_packages() {
    [ -n "$PIP_LOG" ] && [ -f "$PIP_LOG" ] || return 0
    {
        # "ERROR: No matching distribution found for cffi>=1.12"
        sed -n 's/.*[Nn]o matching distribution found for \([A-Za-z0-9._-]*\).*/\1/p' "$PIP_LOG"
        # A resolver conflict lists them under a trailing "...for your environment:" block.
        sed -n '/no matching distributions available/,$ s/^ *\([A-Za-z][A-Za-z0-9._-]*\) *$/\1/p' \
            "$PIP_LOG"
    } | sort -u | tr '\n' ' ' | sed 's/ *$//'
}

python_report() {
    "${VENV}/bin/python" - <<'PYEOF' 2>/dev/null || true
import platform, sysconfig
print(f"  Python:   {platform.python_version()} ({sysconfig.get_platform()})")
print(f"  Machine:  {platform.machine()} / {platform.libc_ver()[0] or 'unknown libc'}")
PYEOF
}

pip_failed() {
    local index="${EDGEKIT_PIP_INDEX_URL:-https://pypi.org/simple}"

    if pip_resolution_failed; then
        local missing option=1
        missing="$(pip_missing_packages)"
        printf '\n%s✗ No usable build of %s for this system.%s\n' \
            "$C_RED" "${missing:-a dependency}" "$C_RESET" >&2
        python_report >&2
        printf '  Index:    %s\n\n' "$index" >&2
        printf '  The index answered — it simply has no build of that for this Python on this\n' >&2
        printf '  machine, and building it from source did not work either. What is left:\n\n' >&2

        printf '   %d. Use a Python the packages publish wheels for. %s is the safe choice\n' \
            "$option" "python3.12" >&2
        printf '      on Debian and Ubuntu:\n' >&2
        printf '         sudo apt install python3.12 python3.12-venv\n' >&2
        printf '         sudo EDGEKIT_PYTHON=python3.12 %s\n\n' "$SELF" >&2
        option=$((option + 1))

        if [ -n "${EDGEKIT_PIP_INDEX_URL:-}" ]; then
            printf '   %d. %s is a mirror, and mirrors carry only part of PyPI.\n' \
                "$option" "${EDGEKIT_PIP_INDEX_URL}" >&2
            printf '      PyPI itself was tried as a fallback and did not work either, so this\n' >&2
            printf '      is unlikely to be the cause — but you can force it:\n' >&2
            printf '         sudo EDGEKIT_PIP_INDEX_URL=https://pypi.org/simple %s\n\n' \
                "$SELF" >&2
            option=$((option + 1))
        fi

        printf '   %d. Install the build toolchain by hand and re-run — the automatic attempt\n' \
            "$option" >&2
        printf '      above may have failed for its own reasons:\n' >&2
        printf '         sudo apt install build-essential python3-dev libffi-dev libssl-dev\n' >&2
        printf '         sudo %s\n\n' "$SELF" >&2
        printf '  Full pip output: %s\n' "$PIP_LOG" >&2
        # Keep the log this time: it is the evidence for whichever route comes next.
        PIP_LOG=""
        exit 1
    fi

    die "pip could not install $1 from ${index}.

  Usually this is the network, not the package. Check reachability:
      curl -sS -m 20 -o /dev/null -w '%{http_code}\n' ${index}/
  If PyPI is slow or blocked from this server, re-run against a mirror, e.g.:
      sudo EDGEKIT_PIP_INDEX_URL=https://mirror.example.org/pypi/simple ${SELF}
  Or just give it longer:
      sudo EDGEKIT_PIP_TIMEOUT=120 EDGEKIT_PIP_ATTEMPTS=5 ${SELF}"
}

#: Everything needed to build a small C extension (cffi is the one that usually needs it).
install_build_toolchain() {
    local packages=(build-essential libffi-dev libssl-dev pkg-config)
    local headers
    headers="$(python_dev_package)"
    apt_options
    # The versioned -dev package matches the interpreter the venv was built from; the
    # unversioned one is right when that is the distro's own python3.
    if [ -n "$headers" ] && apt_get install -y --no-install-recommends "$headers"; then
        packages+=()
    else
        packages+=(python3-dev)
    fi
    apt_get install -y --no-install-recommends "${packages[@]}"
}

python_dev_package() {
    local version
    version="$("${VENV}/bin/python" -c \
        'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    [ -n "$version" ] && printf 'python%s-dev' "$version"
}

#: Second chances for a resolution failure, cheapest and most likely first.
recover_pip_resolution() {
    pip_resolution_failed || return 1

    local missing
    missing="$(pip_missing_packages)"
    warn "no usable build of ${missing:-a dependency} in this index"

    # 1. A mirror carrying only part of PyPI is the common cause, and costs nothing to rule
    #    out. PyPI itself has every wheel every package ever published.
    if [ -n "${EDGEKIT_PIP_INDEX_URL:-}" ]; then
        local mirror="${EDGEKIT_PIP_INDEX_URL}"
        info "retrying against PyPI instead of ${mirror}"
        unset EDGEKIT_PIP_INDEX_URL
        pip_options
        if pip_install "$@"; then
            ok "installed from PyPI — ${mirror} is missing builds for this system"
            return 0
        fi
        export EDGEKIT_PIP_INDEX_URL="$mirror"
        pip_options
        pip_resolution_failed || return 1
    fi

    # 2. No wheel for this Python or this architecture. pip can build from source, given a
    #    compiler and the development headers.
    info "installing a compiler toolchain so pip can build ${missing:-them} from source"
    if ! install_build_toolchain; then
        warn "could not install the build toolchain"
        return 1
    fi
    ok "build toolchain installed"
    if pip_install "$@"; then
        ok "built ${missing:-the missing dependencies} from source"
        return 0
    fi
    return 1
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
    # A requested interpreter needs its own venv module; the distro splits them.
    if [ -n "${EDGEKIT_PYTHON:-}" ] && [ "${PYTHON_BIN}" != "python3" ]; then
        packages+=("${PYTHON_BIN}" "${PYTHON_BIN}-venv")
    fi

    info "[2/3] installing packages: ${packages[*]}"
    apt_get install -y --no-install-recommends "${packages[@]}" || apt_failed install
    ok "system packages installed"

    info "[3/3] verifying Python"
    command -v "$PYTHON_BIN" >/dev/null 2>&1 \
        || die "EDGEKIT_PYTHON=${PYTHON_BIN} is not on PATH after installing packages."
    local python_version
    python_version="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    case "$python_version" in
        3.1[0-9]|3.[2-9][0-9]) ok "Python $python_version ($PYTHON_BIN)" ;;
        *) die "Python 3.10 or newer is required; ${PYTHON_BIN} is $python_version." ;;
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
    if [ -x "${VENV}/bin/python" ] && ! venv_matches_interpreter; then
        # Only reachable when EDGEKIT_PYTHON asks for an interpreter the venv was not built
        # from. The venv is a build artifact — config and data live outside it.
        warn "rebuilding the virtualenv with ${PYTHON_BIN}"
        rm -rf -- "${VENV}"
    fi
    if [ ! -x "${VENV}/bin/python" ]; then
        info "[1/4] creating virtualenv at ${VENV}"
        "${PYTHON_BIN}" -m venv "${VENV}" \
            || die "Could not create a virtualenv with ${PYTHON_BIN}.
  Install it first:  sudo apt install ${PYTHON_BIN} ${PYTHON_BIN}-venv"
        ok "virtualenv created ($("${VENV}/bin/python" -V 2>&1))"
    else
        info "[1/4] reusing existing virtualenv at ${VENV}"
        ok "virtualenv ready ($("${VENV}/bin/python" -V 2>&1))"
    fi

    pip_options
    info "[2/4] upgrading pip, setuptools, wheel"
    pip_install --upgrade pip setuptools wheel || pip_failed "pip, setuptools, wheel"
    ok "pip tooling upgraded"

    info "[3/4] installing edgekit and Python dependencies (this takes a minute)"
    if ! pip_install "${SOURCE_DIR}"; then
        recover_pip_resolution "${SOURCE_DIR}" || pip_failed "edgekit and its dependencies"
    fi
    ok "Python package installed"

    info "[4/4] linking edgekit onto PATH"
    # A stable path on PATH means `edgekit` works for the operator and in the systemd unit.
    ln -sf "${BIN}" /usr/local/bin/edgekit
    ok "$("${BIN}" version) → /usr/local/bin/edgekit"
}

#: False when EDGEKIT_PYTHON names a different interpreter than the venv was built from.
venv_matches_interpreter() {
    [ -n "${EDGEKIT_PYTHON:-}" ] || return 0
    command -v "$PYTHON_BIN" >/dev/null 2>&1 || return 0

    local wanted current
    wanted="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
    current="$("${VENV}/bin/python" -c \
        'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
    [ -n "$wanted" ] && [ -n "$current" ] && [ "$wanted" != "$current" ] && return 1
    return 0
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
