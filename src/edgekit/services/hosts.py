"""Proxy host lifecycle: DNS record, NPM proxy host, and local record, kept in step.

Adding a service is the guide's §20 workflow reduced to one call: point DNS at the edge,
create the NPM proxy host against the peer's tunnel address, and attach the origin
certificate. Each external side-effect records its identifier locally so a later edit
updates rather than duplicates.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Config
from ..models import AuditLog, Peer, ProxyHost, Setting
from .cloudflare import CloudflareClient, CloudflareError
from .npm import NPMClient, ProxyHostSpec

log = logging.getLogger("edgekit.hosts")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

SETTING_CERT_ID = "npm_certificate_id"
SETTING_CERT_NAME = "npm_certificate_name"
SETTING_CERT_EXPIRY = "npm_certificate_expiry"


class HostError(RuntimeError):
    pass


def validate_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise HostError(f"{domain!r} is not a valid hostname")
    return domain


def validate_port(port: int) -> int:
    port = int(port)
    if not 0 < port < 65536:
        raise HostError("Port must be between 1 and 65535")
    return port


def get_setting(session: Session, key: str, default: str = "") -> str:
    row = session.get(Setting, key)
    return row.value if row else default


def set_setting(session: Session, key: str, value: str) -> None:
    row = session.get(Setting, key)
    if row:
        row.value = value
    else:
        session.add(Setting(key=key, value=value))


class HostService:
    def __init__(self, session: Session, config: Config) -> None:
        self.session = session
        self.config = config

    # ---------------------------------------------------------------- queries

    def list(self) -> list[ProxyHost]:
        return list(self.session.scalars(select(ProxyHost).order_by(ProxyHost.domain)))

    def get(self, host_id: int) -> ProxyHost:
        host = self.session.get(ProxyHost, host_id)
        if host is None:
            raise HostError(f"No proxy host with id {host_id}")
        return host

    def certificate_id(self) -> int | None:
        raw = get_setting(self.session, SETTING_CERT_ID)
        return int(raw) if raw.isdigit() else None

    # ---------------------------------------------------------------- clients

    def _npm_client(self) -> NPMClient:
        npm = self.config.npm
        if not (npm.admin_email and npm.admin_password):
            raise HostError(
                "Nginx Proxy Manager credentials are not configured. Run `edgekit setup` "
                "or set them in the panel under Settings."
            )
        return NPMClient(npm.api_base, npm.admin_email, npm.admin_password)

    def _cloudflare_client(self) -> CloudflareClient | None:
        cf = self.config.cloudflare
        if not (cf.enabled and cf.api_token and cf.zone_id):
            return None
        return CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key)

    # ---------------------------------------------------------------- mutations

    async def create(
        self,
        *,
        domain: str,
        forward_port: int,
        peer_id: int | None = None,
        forward_host: str | None = None,
        scheme: str = "http",
        force_ssl: bool = True,
        http2: bool = True,
        websockets: bool = True,
        block_exploits: bool = True,
        manage_dns: bool = True,
        actor: str = "system",
    ) -> ProxyHost:
        domain = validate_domain(domain)
        forward_port = validate_port(forward_port)
        if scheme not in ("http", "https"):
            raise HostError("Scheme must be http or https")

        if self.session.scalar(select(ProxyHost).where(ProxyHost.domain == domain)):
            raise HostError(f"{domain} is already configured")

        peer: Peer | None = None
        if peer_id is not None:
            peer = self.session.get(Peer, peer_id)
            if peer is None:
                raise HostError(f"No peer with id {peer_id}")
            forward_host = peer.address
        if not forward_host:
            raise HostError("Either a peer or an explicit forward host is required")

        host = ProxyHost(
            domain=domain,
            peer_id=peer.id if peer else None,
            forward_host=forward_host,
            forward_port=forward_port,
            scheme=scheme,
            force_ssl=force_ssl,
            http2=http2,
            websockets=websockets,
            block_exploits=block_exploits,
        )
        self.session.add(host)
        self.session.flush()

        await self._push(host, manage_dns=manage_dns)
        self.session.add(
            AuditLog(actor=actor, action="host.create", target=domain,
                     detail=f"-> {host.target}")
        )
        return host

    async def update(
        self,
        host_id: int,
        *,
        peer_id: int | None | str = "unset",
        forward_host: str | None = None,
        forward_port: int | None = None,
        scheme: str | None = None,
        force_ssl: bool | None = None,
        http2: bool | None = None,
        websockets: bool | None = None,
        block_exploits: bool | None = None,
        manage_dns: bool = True,
        actor: str = "system",
    ) -> ProxyHost:
        host = self.get(host_id)

        if peer_id != "unset":
            if peer_id is None:
                host.peer_id = None
            else:
                peer = self.session.get(Peer, int(peer_id))
                if peer is None:
                    raise HostError(f"No peer with id {peer_id}")
                host.peer_id = peer.id
                host.forward_host = peer.address
        if forward_host:
            host.forward_host = forward_host
        if forward_port is not None:
            host.forward_port = validate_port(forward_port)
        if scheme is not None:
            if scheme not in ("http", "https"):
                raise HostError("Scheme must be http or https")
            host.scheme = scheme
        for attr, value in (
            ("force_ssl", force_ssl),
            ("http2", http2),
            ("websockets", websockets),
            ("block_exploits", block_exploits),
        ):
            if value is not None:
                setattr(host, attr, value)

        self.session.flush()
        await self._push(host, manage_dns=manage_dns)
        self.session.add(AuditLog(actor=actor, action="host.update", target=host.domain))
        return host

    async def delete(self, host_id: int, *, remove_dns: bool = False, actor: str = "system") -> str:
        host = self.get(host_id)
        domain = host.domain

        if host.npm_host_id:
            async with self._npm_client() as npm:
                try:
                    await npm.delete_proxy_host(host.npm_host_id)
                except Exception as exc:  # noqa: BLE001 - deletion is best-effort
                    log.warning("could not delete NPM host %s: %s", host.npm_host_id, exc)

        if remove_dns and host.cloudflare_record_id:
            client = self._cloudflare_client()
            if client:
                async with client as cf:
                    try:
                        await cf.delete_dns_record(
                            self.config.cloudflare.zone_id, host.cloudflare_record_id
                        )
                    except CloudflareError as exc:
                        log.warning("could not delete DNS record for %s: %s", domain, exc)

        self.session.delete(host)
        self.session.flush()
        self.session.add(AuditLog(actor=actor, action="host.delete", target=domain))
        log.info("deleted proxy host %s", domain)
        return domain

    # ---------------------------------------------------------------- reconciliation

    async def _push(self, host: ProxyHost, *, manage_dns: bool = True) -> None:
        """Apply a host record to Cloudflare and NPM.

        DNS is done first: if the record cannot be created the proxy host is still useful
        (the operator may manage DNS elsewhere), so a DNS failure is logged and does not
        abort the NPM side.
        """
        if manage_dns:
            client = self._cloudflare_client()
            if client:
                async with client as cf:
                    try:
                        record = await cf.upsert_a_record(
                            self.config.cloudflare.zone_id,
                            host.domain,
                            self.config.server.public_ip,
                            proxied=self.config.cloudflare.proxied,
                        )
                        host.cloudflare_record_id = record.get("id")
                    except CloudflareError as exc:
                        log.warning("DNS record for %s not applied: %s", host.domain, exc)

        spec = ProxyHostSpec(
            domain=host.domain,
            forward_host=host.forward_host,
            forward_port=host.forward_port,
            scheme=host.scheme,
            certificate_id=self.certificate_id(),
            force_ssl=host.force_ssl,
            http2=host.http2,
            websockets=host.websockets,
            block_exploits=host.block_exploits,
        )
        async with self._npm_client() as npm:
            result = await npm.upsert_proxy_host(spec)
        host.npm_host_id = result.get("id")
        host.npm_certificate_id = spec.certificate_id
        self.session.flush()

    async def resync_all(self) -> dict[str, str]:
        """Re-push every host. Used after a certificate rotation or an NPM data loss."""
        outcomes: dict[str, str] = {}
        for host in self.list():
            try:
                await self._push(host)
                outcomes[host.domain] = "ok"
            except Exception as exc:  # noqa: BLE001 - report per host, keep going
                outcomes[host.domain] = f"failed: {exc}"
                log.error("resync failed for %s: %s", host.domain, exc)
        return outcomes

    async def repoint_peer_hosts(self, peer: Peer) -> None:
        """Follow a peer whose tunnel address changed."""
        for host in peer.hosts:
            if host.forward_host != peer.address:
                host.forward_host = peer.address
                await self._push(host, manage_dns=False)
