"""Package installation for Debian/Ubuntu hosts.

Guide steps 2 and 8. Docker is installed from Docker's own APT repository rather than the
distro package, because the distro build often lacks the Compose v2 plugin the guide's
`docker compose` invocations require.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .shell import CommandError, has, run

log = logging.getLogger("edgekit.packages")

DOCKER_GPG = Path("/etc/apt/keyrings/docker.asc")
DOCKER_LIST = Path("/etc/apt/sources.list.d/docker.list")

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
    run(["apt-get", "update", "-qq"], check=True, timeout=600)
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
    run(
        ["apt-get", "install", "-y", "-qq", "--no-install-recommends", *missing],
        check=True,
        timeout=900,
    )
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
            ["curl", "-fsSL", f"https://download.docker.com/linux/{distro}/gpg"],
            check=True,
            timeout=120,
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
    run(["apt-get", "update", "-qq"], check=True, timeout=600)
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
