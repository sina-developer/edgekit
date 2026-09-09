"""Package installation for Debian/Ubuntu hosts.

Guide steps 2 and 8. Docker is installed from Docker's own APT repository rather than the
distro package, because the distro build often lacks the Compose v2 plugin the guide's
`docker compose` invocations require.
"""

from __future__ import annotations

import functools
import logging
import os
import time
from collections.abc import Sequence
from pathlib import Path

from .shell import CommandError, Result, has, run

log = logging.getLogger("edgekit.packages")

DOCKER_GPG = Path("/etc/apt/keyrings/docker.asc")
DOCKER_LIST = Path("/etc/apt/sources.list.d/docker.list")

#: A freshly booted VPS is usually mid-`unattended-upgrade`, which holds the dpkg lock for
#: minutes. Setup waits it out rather than failing halfway through provisioning.
APT_LOCK_WAIT = int(os.environ.get("EDGEKIT_APT_LOCK_WAIT", "900"))
APT_LOCK_POLL = 5
APT_LOCK_FILES = (
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/cache/apt/archives/lock",
    "/var/lib/apt/lists/lock",
)
_LOCK_MARKERS = (
    "could not get lock",
    "frontend lock",
    "another process using it",
    "unable to lock",
)

BASE_PACKAGES = ("ca-certificates", "curl", "gnupg", "iproute2", "iptables")
WIREGUARD_PACKAGES = ("wireguard", "wireguard-tools")
DOCKER_PACKAGES = (
    "docker-ce",
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
)


class UnsupportedPlatform(RuntimeError):
    pass


def apt_lock_holder() -> str | None:
    """PID holding an apt/dpkg lock, or None. Best effort — detection is only advisory."""
    if has("fuser"):
        for path in APT_LOCK_FILES:
            if not Path(path).exists():
                continue
            output = run(["fuser", path], timeout=30).stdout
            pids = [token for token in output.split() if token.isdigit()]
            if pids:
                return pids[0]
        return None
    if has("pgrep"):
        patterns = (
            ["-x", "apt|apt-get|aptitude|dpkg|unattended-upgrade"],
            ["-f", "unattended-upgrade"],
        )
        for pattern in patterns:
            output = run(["pgrep", *pattern], timeout=30).stdout
            pids = [token for token in output.split() if token.isdigit()]
            if pids:
                return pids[0]
    return None


def wait_for_apt_lock(deadline: float) -> None:
    """Block until no other process holds the apt lock, or ``deadline`` passes."""
    pid = apt_lock_holder()
    if pid is None:
        return
    name = _process_name(pid)
    log.warning("apt: %s (pid %s) holds the dpkg lock — waiting for it to finish", name, pid)
    while time.monotonic() < deadline:
        time.sleep(APT_LOCK_POLL)
        if apt_lock_holder() is None:
            log.info("apt: lock released")
            return
    log.warning("apt: still locked after %ss — trying anyway", APT_LOCK_WAIT)


def _process_name(pid: str) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip() or "process"
    except OSError:
        return "process"


def apt_argv(args: Sequence[str]) -> list[str]:
    argv = ["apt-get", "-o", "Acquire::Retries=3"]
    if _apt_has_lock_timeout():
        # apt 2.0+ (Debian 11, Ubuntu 20.04) waits for the lock itself, which closes the race
        # between wait_for_apt_lock and the command that follows it.
        argv += ["-o", f"DPkg::Lock::Timeout={APT_LOCK_WAIT}"]
    return [*argv, *args]


@functools.lru_cache(maxsize=1)
def _apt_has_lock_timeout() -> bool:
    version = run(["dpkg-query", "-W", "-f=${Version}", "apt"]).stdout.strip()
    if not version:
        return False
    return run(["dpkg", "--compare-versions", version, "ge", "2.0"]).ok


def apt(args: Sequence[str], *, timeout: int) -> Result:
    """Run apt-get, waiting out whoever holds the lock and retrying if one takes it mid-run."""
    deadline = time.monotonic() + APT_LOCK_WAIT
    attempt = 0
    while True:
        wait_for_apt_lock(deadline)
        result = run(apt_argv(args), timeout=timeout)
        if result.ok:
            return result
        if not _is_lock_error(result) or time.monotonic() >= deadline:
            raise CommandError(result)
        attempt += 1
        log.warning(
            "apt: lock taken by another process — retry %s in %ss", attempt, APT_LOCK_POLL
        )
        time.sleep(APT_LOCK_POLL)


def _is_lock_error(result: Result) -> bool:
    text = f"{result.stderr}\n{result.stdout}".lower()
    return any(marker in text for marker in _LOCK_MARKERS)


def os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"')
    return data


def require_debian_like() -> dict[str, str]:
    info = os_release()
    family = {info.get("ID", ""), *info.get("ID_LIKE", "").split()}
    if not family & {"debian", "ubuntu", "raspbian"}:
        raise UnsupportedPlatform(
            f"edgekit targets Debian/Ubuntu hosts; detected ID={info.get('ID', 'unknown')!r}. "
            "Install WireGuard and Docker manually, then re-run with --skip-packages."
        )
    return info


def apt_update(max_age_seconds: int = 3600) -> None:
    """Refresh the package index, skipping if it was refreshed recently."""
    stamp = Path("/var/lib/apt/periodic/update-success-stamp")
    lists = Path("/var/lib/apt/lists")
    newest = 0.0
    for candidate in (stamp, lists):
        if candidate.exists():
            newest = max(newest, candidate.stat().st_mtime)
    if newest and (time.time() - newest) < max_age_seconds:
        log.info("apt: package index is fresh — skipping update")
        return
    log.info("apt: refreshing package index")
    apt(["update", "-qq"], timeout=600)
    log.info("apt: package index updated")


def apt_install(packages: tuple[str, ...]) -> None:
    missing = [p for p in packages if not _installed(p)]
    if not missing:
        log.info("apt: already installed — %s", ", ".join(packages))
        return
    present = [p for p in packages if p not in missing]
    if present:
        log.info("apt: already installed — %s", ", ".join(present))
    log.info("apt: installing — %s", ", ".join(missing))
    apt(["install", "-y", "-qq", "--no-install-recommends", *missing], timeout=900)
    log.info("apt: installed — %s", ", ".join(missing))


def _installed(package: str) -> bool:
    result = run(["dpkg-query", "-W", "-f=${Status}", package])
    return result.ok and "install ok installed" in result.stdout


def install_base() -> None:
    log.info("packages: base tools")
    require_debian_like()
    apt_update()
    apt_install(BASE_PACKAGES)
    log.info("packages: base tools ready")


def install_wireguard() -> None:
    """Guide §2."""
    log.info("packages: WireGuard")
    if has("wg") and has("wg-quick"):
        version = wireguard_version() or "present"
        log.info("packages: WireGuard already present (%s)", version)
        return
    apt_update()
    apt_install(WIREGUARD_PACKAGES)
    version = wireguard_version() or "installed"
    log.info("packages: WireGuard ready (%s)", version)


def wireguard_version() -> str | None:
    result = run(["wg", "--version"])
    return result.stdout.strip() if result.ok else None


def install_docker() -> None:
    """Guide §8, using Docker's official APT repository."""
    log.info("packages: Docker Engine + Compose")
    if has("docker") and run(["docker", "compose", "version"]).ok:
        engine, compose = docker_versions()
        log.info(
            "packages: Docker already present (%s / %s)",
            engine or "docker",
            compose or "compose",
        )
        return

    info = require_debian_like()
    # Derivatives (Raspbian, Linux Mint) need the upstream Debian/Ubuntu codename.
    family = {info.get("ID"), *info.get("ID_LIKE", "").split()}
    distro = "ubuntu" if "ubuntu" in family else "debian"
    codename = info.get("VERSION_CODENAME") or info.get("UBUNTU_CODENAME") or ""
    if not codename:
        raise UnsupportedPlatform(
            "Could not determine the distribution codename from /etc/os-release; "
            "install Docker manually and re-run with --skip-packages."
        )

    install_base()
    DOCKER_GPG.parent.mkdir(parents=True, exist_ok=True)
    if not DOCKER_GPG.exists():
        log.info("docker: downloading APT signing key (%s)", distro)
        result = run(
            [
                "curl",
                "-fsSL",
                "--connect-timeout",
                "20",
                "--retry",
                "3",
                "--retry-delay",
                "5",
                f"https://download.docker.com/linux/{distro}/gpg",
            ],
            check=True,
            timeout=180,
        )
        DOCKER_GPG.write_text(result.stdout)
        DOCKER_GPG.chmod(0o644)
        log.info("docker: signing key saved to %s", DOCKER_GPG)
    else:
        log.info("docker: signing key already present")

    arch = run(["dpkg", "--print-architecture"], check=True).stdout.strip()
    entry = (
        f"deb [arch={arch} signed-by={DOCKER_GPG}] "
        f"https://download.docker.com/linux/{distro} {codename} stable\n"
    )
    if not DOCKER_LIST.exists() or DOCKER_LIST.read_text() != entry:
        log.info("docker: configuring APT repository (%s %s %s)", distro, codename, arch)
        DOCKER_LIST.write_text(entry)
    else:
        log.info("docker: APT repository already configured")

    log.info("docker: refreshing package index for Docker repo")
    apt(["update", "-qq"], timeout=600)
    apt_install(DOCKER_PACKAGES)
    log.info("docker: enabling and starting docker.service")
    run(["systemctl", "enable", "--now", "docker"], check=True)
    engine, compose = docker_versions()
    log.info(
        "packages: Docker ready (%s / %s)",
        engine or "docker",
        compose or "compose",
    )


def docker_versions() -> tuple[str | None, str | None]:
    engine = run(["docker", "--version"])
    compose = run(["docker", "compose", "version"])
    return (
        engine.stdout.strip() if engine.ok else None,
        compose.stdout.strip() if compose.ok else None,
    )


def stop_host_nginx() -> bool:
    """Guide §10 — free ports 80/443 for the NPM container. Returns True if it acted."""
    result = run(["systemctl", "is-active", "--quiet", "nginx"])
    if not result.ok:
        return False
    log.info("stopping host nginx so NPM can bind :80 and :443")
    try:
        run(["systemctl", "stop", "nginx"], check=True)
        run(["systemctl", "disable", "nginx"], check=True)
    except CommandError as exc:
        log.warning("could not disable host nginx: %s", exc)
        return False
    return True
