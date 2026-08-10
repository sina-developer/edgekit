"""Docker Compose lifecycle for the Nginx Proxy Manager stack (guide §9, §10).

Named ``dockerx`` to avoid shadowing the ``docker`` PyPI package for anyone who later adds it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..paths import NPM_DIR
from .shell import CommandError, run

log = logging.getLogger("edgekit.docker")

COMPOSE_FILE = NPM_DIR / "docker-compose.yml"


def compose(*args: str, check: bool = True, timeout: int = 600):
    return run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        check=check,
        timeout=timeout,
        cwd=NPM_DIR if NPM_DIR.exists() else None,
    )


def write_compose_file(content: str) -> Path:
    NPM_DIR.mkdir(parents=True, exist_ok=True)
    if not COMPOSE_FILE.exists() or COMPOSE_FILE.read_text() != content:
        COMPOSE_FILE.write_text(content)
    return COMPOSE_FILE


def validate() -> None:
    """Guide §9's `docker compose config` gate — fail before touching a running stack."""
    compose("config", "--quiet")


def up() -> None:
    compose("up", "-d")


def down() -> None:
    compose("down", check=False)


def restart() -> None:
    compose("restart")


def pull() -> None:
    compose("pull", timeout=900)


def logs(container: str, lines: int = 100) -> str:
    result = run(["docker", "logs", container, "--tail", str(lines)], check=False, timeout=30)
    return result.stdout + result.stderr


def container_state(container: str) -> dict[str, object]:
    """Inspect a container, returning ``{"exists": False}`` when it is not present."""
    result = run(["docker", "inspect", container], check=False, timeout=30)
    if not result.ok:
        return {"exists": False, "running": False, "status": "absent"}
    try:
        data = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        return {"exists": False, "running": False, "status": "unreadable"}

    state = data.get("State", {})
    return {
        "exists": True,
        "running": bool(state.get("Running")),
        "status": state.get("Status", "unknown"),
        "started_at": state.get("StartedAt"),
        "restarts": data.get("RestartCount", 0),
        "image": data.get("Config", {}).get("Image", ""),
    }


def exec_in(container: str, argv: list[str], timeout: int = 30):
    return run(["docker", "exec", container, *argv], check=False, timeout=timeout)


def curl_from_container(container: str, url: str, timeout: int = 8):
    """Guide §17's container-side reachability probe."""
    return exec_in(
        container,
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout",
         str(timeout), url],
        timeout=timeout + 10,
    )


def daemon_running() -> bool:
    try:
        run(["docker", "info"], check=True, timeout=30)
    except CommandError:
        return False
    return True
