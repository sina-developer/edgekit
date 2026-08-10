"""Kernel networking parameters (guide §17)."""

from __future__ import annotations

import logging

from ..paths import SYSCTL_FILE
from .shell import run

log = logging.getLogger("edgekit.sysctl")

REQUIRED = {
    # Without this, the hub will not route packets between the Docker bridge and wg0 —
    # the single most common reason NPM cannot reach a peer.
    "net.ipv4.ip_forward": "1",
    # Docker sets this too, but it is easy to lose to a distro hardening profile.
    "net.ipv4.conf.all.src_valid_mark": "1",
}


def read(key: str) -> str | None:
    result = run(["sysctl", "-n", key])
    return result.stdout.strip() if result.ok else None


def apply() -> None:
    """Write a persistent sysctl drop-in and load it immediately."""
    body = "# Managed by edgekit. Changes here are overwritten on provision.\n"
    body += "".join(f"{key} = {value}\n" for key, value in REQUIRED.items())

    SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not SYSCTL_FILE.exists() or SYSCTL_FILE.read_text() != body:
        SYSCTL_FILE.write_text(body)

    for key, value in REQUIRED.items():
        run(["sysctl", "-w", f"{key}={value}"])
    run(["sysctl", "--system"])


def verify() -> dict[str, bool]:
    return {key: read(key) == value for key, value in REQUIRED.items()}
