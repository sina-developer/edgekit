"""Typed configuration, persisted as YAML at /etc/edgekit/config.yaml.

Secrets are transparently encrypted on save and decrypted on load, so in-memory config always
holds plaintext while on-disk config never does. Fields listed in a model's ``SECRET_FIELDS``
get that treatment.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import stat
from typing import Any, ClassVar

import yaml
from pydantic import BaseModel, Field, field_validator

from .crypto import decrypt, encrypt
from .paths import CONFIG_FILE


class _Section(BaseModel):
    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ()


class WireGuardConfig(_Section):
    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("private_key",)

    interface: str = "wg0"
    subnet: str = "10.50.0.0/24"
    listen_port: int = 51820
    private_key: str = ""
    public_key: str = ""
    #: MTU left unset means "let wg-quick decide", which is correct on most clouds.
    mtu: int | None = None
    #: Sent to peers so they keep NAT bindings alive from behind a home router.
    persistent_keepalive: int = 25

    @field_validator("subnet")
    @classmethod
    def _valid_subnet(cls, value: str) -> str:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4:
            raise ValueError("only IPv4 subnets are supported")
        if net.prefixlen > 30:
            raise ValueError("subnet must be /30 or larger to hold a hub and peers")
        return str(net)

    @field_validator("listen_port", "persistent_keepalive")
    @classmethod
    def _valid_port(cls, value: int) -> int:
        if not 0 < value < 65536:
            raise ValueError("must be between 1 and 65535")
        return value

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.subnet, strict=False)

    @property
    def hub_ip(self) -> str:
        """First usable address in the subnet — the hub always takes it."""
        return str(next(self.network.hosts()))

    @property
    def hub_address(self) -> str:
        return f"{self.hub_ip}/{self.network.prefixlen}"


class NPMConfig(_Section):
    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("admin_password",)

    enabled: bool = True
    http_port: int = 80
    https_port: int = 443
    admin_port: int = 8181
    #: Restricting the admin UI to loopback is the safe default; the panel proxies to it.
    admin_bind: str = "127.0.0.1"
    admin_email: str = ""
    admin_password: str = ""
    image: str = "jc21/nginx-proxy-manager:latest"
    container_name: str = "nginx-proxy-manager"

    @property
    def api_base(self) -> str:
        host = "127.0.0.1" if self.admin_bind in ("127.0.0.1", "0.0.0.0") else self.admin_bind
        return f"http://{host}:{self.admin_port}/api"


class CloudflareConfig(_Section):
    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("api_token", "origin_ca_key")

    enabled: bool = False
    api_token: str = ""
    #: Optional. Cloudflare's Origin CA endpoint historically requires this user-service key;
    #: newer account-scoped tokens with SSL:Edit also work, so we try the token first.
    origin_ca_key: str = ""
    zone_name: str = ""
    zone_id: str = ""
    #: Whether A records are created behind Cloudflare's proxy (orange cloud).
    proxied: bool = True
    manage_ssl_mode: bool = True
    ssl_mode: str = "strict"
    origin_cert_validity_days: int = 5475  # 15 years, Cloudflare's maximum

    @field_validator("ssl_mode")
    @classmethod
    def _valid_mode(cls, value: str) -> str:
        allowed = {"off", "flexible", "full", "strict"}
        if value not in allowed:
            raise ValueError(f"ssl_mode must be one of {sorted(allowed)}")
        return value


class TLSConfig(_Section):
    """An operator-supplied origin certificate.

    Held here so that `edgekit provision` can reinstall it into a rebuilt Nginx Proxy
    Manager without asking again. The certificate is public; only the key is a secret.
    """

    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("certificate_key",)

    certificate: str = ""
    certificate_key: str = ""
    name: str = ""

    @property
    def present(self) -> bool:
        return bool(self.certificate and self.certificate_key)


class PanelConfig(_Section):
    SECRET_FIELDS: ClassVar[tuple[str, ...]] = ("session_secret",)

    #: Loopback by default. Reach it over an SSH tunnel, or bind it to the WireGuard hub IP.
    bind: str = "127.0.0.1"
    port: int = 8088
    session_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    session_max_age_seconds: int = 8 * 3600


class ServerConfig(_Section):
    public_ip: str = ""
    hostname: str = ""
    #: Detected Docker bridge subnet; needed for the container -> WireGuard NAT rules.
    docker_bridge_subnet: str = "172.17.0.0/16"


class Config(BaseModel):
    version: int = 1
    server: ServerConfig = Field(default_factory=ServerConfig)
    wireguard: WireGuardConfig = Field(default_factory=WireGuardConfig)
    npm: NPMConfig = Field(default_factory=NPMConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    #: Off by default. DNS records, SSL mode and the origin certificate are one-time
    #: dashboard actions; the API is available for anyone who wants them automated.
    cloudflare: CloudflareConfig = Field(default_factory=CloudflareConfig)
    panel: PanelConfig = Field(default_factory=PanelConfig)

    # ---------------------------------------------------------------- persistence

    @classmethod
    def load(cls, path: Any = None) -> Config:
        path = path or CONFIG_FILE
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text()) or {}
        return cls.model_validate(cls._map_secrets(raw, decrypt))

    def save(self, path: Any = None) -> None:
        path = path or CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._map_secrets(self.model_dump(mode="json"), encrypt)
        body = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)

        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
        # Atomic replace keeps a crash mid-write from leaving a truncated config behind.
        os.replace(tmp, path)

    @classmethod
    def _map_secrets(cls, data: dict[str, Any], fn) -> dict[str, Any]:
        """Apply ``fn`` to every field a section declares as secret."""
        out = dict(data)
        for name, field in cls.model_fields.items():
            section_cls = field.annotation
            if not (isinstance(section_cls, type) and issubclass(section_cls, _Section)):
                continue
            section = out.get(name)
            if not isinstance(section, dict):
                continue
            section = dict(section)
            for key in section_cls.SECRET_FIELDS:
                if section.get(key):
                    section[key] = fn(section[key])
            out[name] = section
        return out

    # ---------------------------------------------------------------- helpers

    @property
    def configured(self) -> bool:
        """True once setup has produced the minimum viable state."""
        return bool(self.server.public_ip and self.wireguard.private_key)


def load_config() -> Config:
    return Config.load()
