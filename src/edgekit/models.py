"""ORM models: panel users, WireGuard peers, proxy hosts, and the audit trail."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .crypto import decrypt, encrypt


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class EncryptedText(TypeDecorator):
    """Text column whose value is encrypted at rest and decrypted on read."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> Any:
        return encrypt(value) if value else value

    def process_result_value(self, value: Any, dialect) -> Any:
        return decrypt(value) if value else value


class User(Base):
    """A panel operator. Kept deliberately minimal: local accounts, no roles yet."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)


class Peer(Base):
    """A WireGuard client (a Raspberry Pi, a laptop, another VPS) attached to this hub."""

    __tablename__ = "peers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")

    #: Tunnel address without prefix, e.g. "10.50.0.2".
    address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    #: Held only when edgekit generated the keypair, so the panel can re-serve the peer
    #: config and QR code. Peers registered by public key alone leave this empty.
    private_key: Mapped[str | None] = mapped_column(EncryptedText)
    preshared_key: Mapped[str | None] = mapped_column(EncryptedText)

    #: Extra CIDRs routed to this peer beyond its own /32 (e.g. a LAN behind it).
    extra_allowed_ips: Mapped[str] = mapped_column(String(255), default="")
    keepalive: Mapped[int] = mapped_column(Integer, default=25)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    hosts: Mapped[list[ProxyHost]] = relationship(back_populates="peer")

    @property
    def allowed_ips(self) -> str:
        entries = [f"{self.address}/32"]
        entries += [c.strip() for c in self.extra_allowed_ips.split(",") if c.strip()]
        return ", ".join(entries)


class ProxyHost(Base):
    """A public hostname routed through Nginx Proxy Manager to a service behind the tunnel."""

    __tablename__ = "proxy_hosts"
    __table_args__ = (UniqueConstraint("domain", name="uq_proxy_host_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)

    #: Either target a registered peer (preferred) or a raw address.
    peer_id: Mapped[int | None] = mapped_column(ForeignKey("peers.id", ondelete="SET NULL"))
    forward_host: Mapped[str] = mapped_column(String(253), nullable=False)
    forward_port: Mapped[int] = mapped_column(Integer, nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), default="http")

    force_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    http2: Mapped[bool] = mapped_column(Boolean, default=True)
    websockets: Mapped[bool] = mapped_column(Boolean, default=True)
    block_exploits: Mapped[bool] = mapped_column(Boolean, default=True)

    #: Identifiers assigned by the external systems, so we can reconcile instead of duplicate.
    npm_host_id: Mapped[int | None] = mapped_column(Integer)
    npm_certificate_id: Mapped[int | None] = mapped_column(Integer)
    cloudflare_record_id: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    peer: Mapped[Peer | None] = relationship(back_populates="hosts")

    @property
    def target(self) -> str:
        return f"{self.scheme}://{self.forward_host}:{self.forward_port}"


class Setting(Base):
    """Small key/value store for reconciliation state that does not deserve a table."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AuditLog(Base):
    """Append-only record of every state-changing action, panel or CLI."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    actor: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)
