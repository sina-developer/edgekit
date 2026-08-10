"""Filesystem layout.

Every path edgekit owns is declared here so that relocating state (for tests, or for a
non-standard prefix) is a single environment variable rather than a grep across the codebase.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Root override, primarily for tests and for running the CLI unprivileged.
_ROOT = Path(os.environ.get("EDGEKIT_ROOT", "/"))


def _p(*parts: str) -> Path:
    return _ROOT.joinpath(*parts)


CONFIG_DIR = _p("etc", "edgekit")
CONFIG_FILE = CONFIG_DIR / "config.yaml"
SECRET_KEY_FILE = CONFIG_DIR / "secret.key"

STATE_DIR = _p("var", "lib", "edgekit")
DB_FILE = STATE_DIR / "edgekit.db"

LOG_DIR = _p("var", "log", "edgekit")
LOG_FILE = LOG_DIR / "edgekit.log"

WG_DIR = _p("etc", "wireguard")
NPM_DIR = _p("opt", "nginx-proxy-manager")

#: Where a pasted origin certificate is saved, so it exists as a file you can inspect,
#: back up, or re-install from later.
ORIGIN_CERT_FILE = _p("root", "origin.pem")
ORIGIN_KEY_FILE = _p("root", "origin.key")

FIREWALL_SCRIPT = _p("usr", "local", "lib", "edgekit", "firewall.sh")
SYSCTL_FILE = _p("etc", "sysctl.d", "99-edgekit.conf")

SYSTEMD_DIR = _p("etc", "systemd", "system")
PANEL_UNIT = SYSTEMD_DIR / "edgekit-panel.service"
FIREWALL_UNIT = SYSTEMD_DIR / "edgekit-firewall.service"


def ensure_dirs() -> None:
    """Create the directories edgekit writes to, with restrictive permissions on secrets.

    Best-effort by design: read-only commands (``version``, ``status``, ``--help``) run
    unprivileged and must not crash here. Commands that genuinely need to write are gated
    on root separately, and fail with a message that says so.
    """
    for path, mode in (
        (CONFIG_DIR, 0o700),
        (STATE_DIR, 0o700),
        (LOG_DIR, 0o750),
    ):
        try:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        except (PermissionError, OSError):
            continue
