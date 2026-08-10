"""Peer lifecycle: allocate, persist, render, apply.

The database is authoritative. ``wg0.conf`` is regenerated from it on every change and
hot-applied with ``wg syncconf``, so the file and the running interface can never drift for
long, and a peer edit does not interrupt tunnels that are already up.
"""

from __future__ import annotations

import ipaddress
import logging
import re

import segno
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Config
from ..models import AuditLog, Peer
from ..rendering import render
from ..system import wireguard as wg

log = logging.getLogger("edgekit.peers")

#: 1–64 characters. Must start and end alphanumeric so names stay safe as filenames and as
#: comment lines in wg0.conf.
NAME_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9 ._-]{0,62}[a-zA-Z0-9])?$")


class PeerError(RuntimeError):
    pass


def _audit(session: Session, action: str, target: str, detail: str = "", actor: str = "system",
           success: bool = True) -> None:
    session.add(
        AuditLog(actor=actor, action=action, target=target, detail=detail, success=success)
    )


def validate_name(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise PeerError(
            "Peer name must be 1–64 characters of letters, digits, space, dot, dash or "
            "underscore, and must start and end with a letter or digit."
        )
    return name


def validate_extra_allowed_ips(value: str) -> str:
    """Accept a comma-separated CIDR list, normalising and rejecting malformed entries."""
    value = (value or "").strip()
    if not value:
        return ""
    normalised = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            normalised.append(str(ipaddress.ip_network(chunk, strict=False)))
        except ValueError as exc:
            raise PeerError(f"{chunk!r} is not a valid CIDR: {exc}") from exc
    return ", ".join(normalised)


class PeerService:
    def __init__(self, session: Session, config: Config) -> None:
        self.session = session
        self.config = config

    # ---------------------------------------------------------------- queries

    def list(self) -> list[Peer]:
        return list(self.session.scalars(select(Peer).order_by(Peer.address)))

    def get(self, peer_id: int) -> Peer:
        peer = self.session.get(Peer, peer_id)
        if peer is None:
            raise PeerError(f"No peer with id {peer_id}")
        return peer

    def get_by_name(self, name: str) -> Peer | None:
        return self.session.scalar(select(Peer).where(Peer.name == name))

    def taken_addresses(self, exclude_id: int | None = None) -> set[str]:
        query = select(Peer.address)
        if exclude_id is not None:
            query = query.where(Peer.id != exclude_id)
        return set(self.session.scalars(query))

    # ---------------------------------------------------------------- mutations

    def create(
        self,
        name: str,
        *,
        description: str = "",
        address: str | None = None,
        public_key: str | None = None,
        extra_allowed_ips: str = "",
        keepalive: int = 25,
        use_preshared_key: bool = True,
        actor: str = "system",
    ) -> Peer:
        """Register a peer, generating a keypair unless a public key is supplied.

        Supplying ``public_key`` is the more secure path — the private key is then generated
        on the client and never touches this host. Generating here is the convenient path,
        and is what lets the panel hand back a ready-to-paste config and QR code.
        """
        name = validate_name(name)
        if self.get_by_name(name):
            raise PeerError(f"A peer named {name!r} already exists")

        extra_allowed_ips = validate_extra_allowed_ips(extra_allowed_ips)

        if address:
            address = self._validate_address(address)
        else:
            address = wg.next_free_address(self.config.wireguard.subnet, self.taken_addresses())

        private_key = None
        if public_key:
            if not wg.valid_key(public_key):
                raise PeerError("Public key is not a valid 44-character base64 WireGuard key")
        else:
            keypair = wg.generate_keypair()
            private_key, public_key = keypair.private_key, keypair.public_key

        if self.session.scalar(select(Peer).where(Peer.public_key == public_key)):
            raise PeerError("That public key is already registered to another peer")

        peer = Peer(
            name=name,
            description=description.strip(),
            address=address,
            public_key=public_key,
            private_key=private_key,
            preshared_key=wg.generate_preshared_key() if use_preshared_key else None,
            extra_allowed_ips=extra_allowed_ips,
            keepalive=int(keepalive),
        )
        self.session.add(peer)
        self.session.flush()
        _audit(self.session, "peer.create", name, f"address={address}", actor)
        log.info("created peer %s at %s", name, address)
        return peer

    def update(
        self,
        peer_id: int,
        *,
        description: str | None = None,
        extra_allowed_ips: str | None = None,
        keepalive: int | None = None,
        enabled: bool | None = None,
        actor: str = "system",
    ) -> Peer:
        peer = self.get(peer_id)
        if description is not None:
            peer.description = description.strip()
        if extra_allowed_ips is not None:
            peer.extra_allowed_ips = validate_extra_allowed_ips(extra_allowed_ips)
        if keepalive is not None:
            peer.keepalive = int(keepalive)
        if enabled is not None:
            peer.enabled = bool(enabled)
        self.session.flush()
        _audit(self.session, "peer.update", peer.name, actor=actor)
        return peer

    def delete(self, peer_id: int, *, actor: str = "system") -> str:
        peer = self.get(peer_id)
        name = peer.name
        if peer.hosts:
            domains = ", ".join(h.domain for h in peer.hosts)
            raise PeerError(
                f"Peer {name!r} still serves these proxy hosts: {domains}. "
                "Remove or repoint them first."
            )
        self.session.delete(peer)
        self.session.flush()
        _audit(self.session, "peer.delete", name, actor=actor)
        log.info("deleted peer %s", name)
        return name

    def rotate_keys(self, peer_id: int, *, actor: str = "system") -> Peer:
        """Issue a fresh keypair. The peer is offline until it loads the new config."""
        peer = self.get(peer_id)
        keypair = wg.generate_keypair()
        peer.private_key = keypair.private_key
        peer.public_key = keypair.public_key
        peer.preshared_key = wg.generate_preshared_key()
        self.session.flush()
        _audit(self.session, "peer.rotate_keys", peer.name, actor=actor)
        log.warning("rotated keys for peer %s — it must be reconfigured to reconnect", peer.name)
        return peer

    def _validate_address(self, address: str) -> str:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise PeerError(f"{address!r} is not a valid IP address") from exc

        network = self.config.wireguard.network
        if ip not in network:
            raise PeerError(f"{address} is outside the tunnel subnet {network}")
        if str(ip) == self.config.wireguard.hub_ip:
            raise PeerError(f"{address} is reserved for the hub itself")
        if str(ip) in self.taken_addresses():
            raise PeerError(f"{address} is already assigned to another peer")
        return str(ip)

    # ---------------------------------------------------------------- rendering / applying

    def render_interface_config(self) -> str:
        """Render wg0.conf from the database (guide §3)."""
        peers = [p for p in self.list() if p.enabled]
        return render(
            "wg0.conf.j2",
            hub_address=self.config.wireguard.hub_address,
            listen_port=self.config.wireguard.listen_port,
            private_key=self.config.wireguard.private_key,
            mtu=self.config.wireguard.mtu,
            peers=peers,
        )

    def sync(self) -> None:
        """Write wg0.conf and hot-apply it to the running interface."""
        interface = self.config.wireguard.interface
        wg.write_config(interface, self.render_interface_config())
        wg.apply_config(interface)
        log.info("synced %s with %d enabled peer(s)", interface, len(
            [p for p in self.list() if p.enabled]
        ))

    def render_peer_config(self, peer: Peer, *, route_whole_subnet: bool = True) -> str:
        """Render the client-side config (guide §5).

        ``route_whole_subnet`` routes the entire tunnel subnet through the peer's tunnel so it
        can also reach sibling peers via the hub. Setting it False restricts routing to the
        hub address only, which is what the original guide used.
        """
        if not peer.private_key:
            raise PeerError(
                f"Peer {peer.name!r} was registered with a public key only, so edgekit does "
                "not hold its private key and cannot render a client config. Rotate its keys "
                "if you need edgekit to manage them."
            )

        cfg = self.config.wireguard
        allowed = cfg.subnet if route_whole_subnet else f"{cfg.hub_ip}/32"
        return render(
            "peer.conf.j2",
            peer=peer,
            interface=cfg.interface,
            private_key=peer.private_key,
            prefix_len=cfg.network.prefixlen,
            hub_public_key=cfg.public_key,
            endpoint=f"{self.config.server.public_ip}:{cfg.listen_port}",
            allowed_ips=allowed,
            mtu=cfg.mtu,
            dns=None,
        )

    def render_peer_qr(self, peer: Peer, **kwargs) -> str:
        """SVG QR code of the peer config, for the WireGuard mobile apps."""
        config_text = self.render_peer_config(peer, **kwargs)
        qr = segno.make(config_text, error="m")
        # An explicit black-on-white code: scanners need real contrast, and the panel gives
        # the QR a white backing so it stays readable in dark mode too.
        return qr.svg_inline(scale=4, border=2, dark="#000000", light="#ffffff")

    # ---------------------------------------------------------------- runtime status

    def status_map(self) -> dict[str, wg.PeerStatus]:
        return {p.public_key: p for p in wg.status(self.config.wireguard.interface)}
