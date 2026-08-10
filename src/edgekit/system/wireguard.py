"""WireGuard interface and peer management (guide §3, §5, §6).

Config generation is deliberately full-file: the database is the source of truth and
``wg0.conf`` is a rendered artifact. Applying changes uses ``wg syncconf`` rather than
``wg-quick down && up`` so that adding a peer never drops the tunnels already established —
which matters a lot once the hub is carrying live traffic.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from ..paths import WG_DIR
from .shell import CommandError, run, service_enabled, systemctl

log = logging.getLogger("edgekit.wireguard")

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw]=$")


class WireGuardError(RuntimeError):
    pass


@dataclass(slots=True)
class KeyPair:
    private_key: str
    public_key: str


@dataclass(slots=True)
class PeerStatus:
    public_key: str
    endpoint: str | None
    allowed_ips: str
    latest_handshake: int  # unix seconds; 0 means never
    rx_bytes: int
    tx_bytes: int

    @property
    def connected(self) -> bool:
        """A peer is considered live if it handshook within the last three minutes.

        WireGuard rekeys every ~2 minutes when traffic flows, so 180s avoids flapping
        while still catching a genuinely dead tunnel quickly.
        """
        return self.latest_handshake > 0 and (time.time() - self.latest_handshake) < 180


def valid_key(key: str) -> bool:
    """WireGuard keys are 32 bytes, base64-encoded to 44 characters."""
    return bool(KEY_RE.match(key or ""))


def generate_keypair() -> KeyPair:
    private_key = run(["wg", "genkey"], check=True).stdout.strip()
    public_key = run(["wg", "pubkey"], input_text=private_key, check=True).stdout.strip()
    return KeyPair(private_key=private_key, public_key=public_key)


def generate_preshared_key() -> str:
    """An extra symmetric layer per peer; cheap, and hardens against future quantum attacks."""
    return run(["wg", "genpsk"], check=True).stdout.strip()


def derive_public_key(private_key: str) -> str:
    return run(["wg", "pubkey"], input_text=private_key, check=True).stdout.strip()


def config_path(interface: str) -> Path:
    return WG_DIR / f"{interface}.conf"


def write_config(interface: str, content: str) -> Path:
    """Write wg0.conf atomically with 0600 (guide §5's chmod, applied by construction)."""
    WG_DIR.mkdir(parents=True, exist_ok=True)
    WG_DIR.chmod(0o700)

    path = config_path(interface)
    tmp = path.with_suffix(".conf.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    os.replace(tmp, path)
    return path


def interface_exists(interface: str) -> bool:
    return run(["ip", "link", "show", interface]).ok


def bring_up(interface: str) -> None:
    """Start the interface through systemd so ``wg-quick@`` tracks it as active.

    Calling ``wg-quick up`` directly leaves the unit inactive: peers can handshake
    while the panel reports WireGuard as down. ``systemctl start`` is the same
    ``wg-quick up`` under the hood, but systemd records the unit as running.
    """
    if interface_exists(interface):
        log.debug("%s already up", interface)
        return
    systemctl("start", f"wg-quick@{interface}", check=True)


def bring_down(interface: str) -> None:
    if not interface_exists(interface):
        return
    # Prefer systemd so the unit state matches the device. If the interface was
    # brought up outside systemd, ``systemctl stop`` is a no-op and we fall back.
    systemctl("stop", f"wg-quick@{interface}")
    if not interface_exists(interface):
        return
    run(["wg-quick", "down", interface], check=True)


def enable_at_boot(interface: str) -> None:
    unit = f"wg-quick@{interface}"
    if not service_enabled(unit):
        systemctl("enable", unit, check=True)


def apply_config(interface: str) -> None:
    """Hot-apply the on-disk config to a running interface without dropping peers.

    ``wg-quick strip`` renders the config with wg-quick-only directives removed, which is
    exactly what ``wg syncconf`` expects. If the interface is not up yet, we simply start it.
    """
    if not interface_exists(interface):
        bring_up(interface)
        return

    stripped = run(["wg-quick", "strip", interface], check=True).stdout
    try:
        run(["wg", "syncconf", interface, "/dev/stdin"], input_text=stripped, check=True)
    except CommandError:
        # /dev/stdin is unavailable in some minimal containers; fall back to a temp file.
        tmp = WG_DIR / f".{interface}.sync"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as fh:
            fh.write(stripped)
        try:
            run(["wg", "syncconf", interface, str(tmp)], check=True)
        finally:
            tmp.unlink(missing_ok=True)


def status(interface: str) -> list[PeerStatus]:
    """Parse ``wg show <iface> dump`` into structured peer status."""
    result = run(["wg", "show", interface, "dump"])
    if not result.ok:
        return []

    peers: list[PeerStatus] = []
    lines = result.stdout.strip().splitlines()
    # First line describes the interface itself; the rest are peers.
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        peers.append(
            PeerStatus(
                public_key=fields[0],
                endpoint=None if fields[2] == "(none)" else fields[2],
                allowed_ips=fields[3],
                latest_handshake=int(fields[4] or 0),
                rx_bytes=int(fields[5] or 0),
                tx_bytes=int(fields[6] or 0),
            )
        )
    return peers


def interface_up(interface: str) -> bool:
    """True when the WireGuard network device is present.

    Status follows the live interface (what ``wg show`` and peer handshakes use),
    not whether the ``wg-quick@`` systemd unit happens to report active. The unit
    can be inactive after a direct ``wg-quick up`` or a provision that only
    ``enable``d the unit — while tunnels are still carrying traffic.
    """
    return interface_exists(interface)


def ping(address: str, count: int = 2, timeout: int = 5) -> bool:
    """Guide §6 reachability check."""
    return run(
        ["ping", "-c", str(count), "-W", str(timeout), address],
        timeout=timeout * count + 5,
    ).ok


def next_free_address(subnet: str, taken: set[str]) -> str:
    """Allocate the lowest unused host address, skipping the hub's own address.

    Raises when the subnet is exhausted rather than silently reusing an address, because a
    duplicate tunnel IP produces confusing intermittent routing rather than a clean failure.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = network.hosts()
    hub = str(next(hosts))
    reserved = taken | {hub}
    for candidate in hosts:
        if str(candidate) not in reserved:
            return str(candidate)
    raise WireGuardError(
        f"No free addresses left in {subnet} ({len(reserved)} in use). "
        "Widen the subnet in /etc/edgekit/config.yaml and re-run `edgekit provision`."
    )
