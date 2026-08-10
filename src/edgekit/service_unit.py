"""systemd unit for the panel."""

from __future__ import annotations

import sys

from .paths import CONFIG_DIR, PANEL_UNIT, STATE_DIR
from .system.shell import systemctl

UNIT_TEMPLATE = """[Unit]
Description=edgekit management panel
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={executable} serve
Restart=on-failure
RestartSec=5
User=root

# The panel edits /etc/wireguard and calls wg/iptables, so it cannot be unprivileged.
# These directives remove everything it does *not* need.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=no
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
ProtectSystem=full
ReadWritePaths={config_dir} {state_dir} /etc/wireguard /opt/nginx-proxy-manager

[Install]
WantedBy=multi-user.target
"""


def render_unit(executable: str | None = None) -> str:
    executable = executable or _edgekit_path()
    return UNIT_TEMPLATE.format(
        executable=executable,
        config_dir=CONFIG_DIR,
        state_dir=STATE_DIR,
    )


def _edgekit_path() -> str:
    """Resolve the console script next to the running interpreter.

    Using the venv's own script keeps the unit correct whether edgekit was installed into
    /opt/edgekit by the installer or into a developer's virtualenv.
    """
    candidate = f"{sys.prefix}/bin/edgekit"
    return candidate


def install(enable: bool = True, start: bool = True) -> None:
    unit = render_unit()
    if not PANEL_UNIT.exists() or PANEL_UNIT.read_text() != unit:
        PANEL_UNIT.parent.mkdir(parents=True, exist_ok=True)
        PANEL_UNIT.write_text(unit)
    systemctl("daemon-reload")
    if enable:
        systemctl("enable", "edgekit-panel.service")
    if start:
        systemctl("restart", "edgekit-panel.service")


def uninstall() -> None:
    systemctl("disable", "--now", "edgekit-panel.service")
    PANEL_UNIT.unlink(missing_ok=True)
    systemctl("daemon-reload")
