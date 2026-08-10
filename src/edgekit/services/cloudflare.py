"""Cloudflare API client (guide §12, §13, §14).

Covers the three things the guide does in the dashboard: A records pointing at the edge,
SSL/TLS mode set to Full (strict), and an Origin CA certificate for the origin.

The Origin CA private key is generated *on this host* and only a CSR is sent to Cloudflare.
Cloudflare will happily generate the keypair for you and return the private key over the
wire, but there is no reason to let a private key exist anywhere it does not have to.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("edgekit.cloudflare")

API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    """A Cloudflare API call failed. Carries the API's own error list when present."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None) -> None:
        self.errors = errors or []
        if self.errors:
            detail = "; ".join(
                f"[{e.get('code')}] {e.get('message')}" for e in self.errors
            )
            message = f"{message} — {detail}"
        super().__init__(message)


@dataclass(slots=True)
class OriginCertificate:
    certificate_pem: str
    private_key_pem: str
    hostnames: list[str]
    expires_on: str | None = None


def generate_csr(hostnames: list[str], key_size: int = 2048) -> tuple[str, str]:
    """Generate an RSA key and a CSR covering ``hostnames``.

    Returns ``(csr_pem, private_key_pem)``. RSA-2048 rather than ECDSA because Cloudflare's
    ``origin-rsa`` request type has the broadest compatibility with origin servers.
    """
    if not hostnames:
        raise ValueError("at least one hostname is required")

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return csr_pem, key_pem


def certificate_expiry(certificate_pem: str) -> dt.datetime | None:
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except ValueError:
        return None
    return cert.not_valid_after_utc


class CloudflareClient:
    def __init__(
        self,
        api_token: str,
        *,
        origin_ca_key: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.api_token = api_token
        self.origin_ca_key = origin_ca_key
        self._client = httpx.AsyncClient(base_url=API_BASE, timeout=timeout)

    async def __aenter__(self) -> CloudflareClient:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---------------------------------------------------------------- plumbing

    async def _request(
        self, method: str, path: str, *, use_origin_ca_key: bool = False, **kwargs
    ) -> Any:
        if use_origin_ca_key and self.origin_ca_key:
            headers = {"X-Auth-User-Service-Key": self.origin_ca_key}
        else:
            headers = {"Authorization": f"Bearer {self.api_token}"}
        headers.update(kwargs.pop("headers", {}))

        response = await self._client.request(method, path, headers=headers, **kwargs)
        try:
            body = response.json()
        except ValueError:
            raise CloudflareError(
                f"Cloudflare {method} {path} returned non-JSON ({response.status_code})"
            ) from None

        if not body.get("success", False):
            raise CloudflareError(
                f"Cloudflare {method} {path} failed ({response.status_code})",
                body.get("errors"),
            )
        return body.get("result")

    # ---------------------------------------------------------------- account / zone

    async def verify_token(self) -> dict[str, Any]:
        """Fail fast during setup with a clear message rather than at first use."""
        return await self._request("GET", "/user/tokens/verify")

    async def list_zones(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/zones", params={"per_page": 50}) or []

    async def get_zone_id(self, zone_name: str) -> str:
        result = await self._request("GET", "/zones", params={"name": zone_name})
        if not result:
            raise CloudflareError(
                f"Zone {zone_name!r} is not visible to this API token. Check the token's "
                "Zone:Read permission and that it is scoped to include this zone."
            )
        return result[0]["id"]

    # ---------------------------------------------------------------- DNS (guide §12)

    async def list_dns_records(self, zone_id: str, *, name: str | None = None) -> list[dict]:
        params: dict[str, Any] = {"per_page": 100}
        if name:
            params["name"] = name
        return await self._request("GET", f"/zones/{zone_id}/dns_records", params=params) or []

    async def upsert_a_record(
        self, zone_id: str, name: str, ip: str, *, proxied: bool = True, ttl: int = 1
    ) -> dict[str, Any]:
        """Create or update the A record for ``name``.

        ``ttl=1`` means "automatic", which is the only value Cloudflare accepts for proxied
        records.
        """
        payload = {
            "type": "A",
            "name": name,
            "content": ip,
            "proxied": proxied,
            "ttl": 1 if proxied else ttl,
            "comment": "Managed by edgekit",
        }
        for record in await self.list_dns_records(zone_id, name=name):
            if record["type"] == "A":
                if (
                    record["content"] == ip
                    and record.get("proxied") == proxied
                ):
                    log.debug("DNS record %s already correct", name)
                    return record
                log.info("updating DNS A record %s -> %s", name, ip)
                return await self._request(
                    "PUT", f"/zones/{zone_id}/dns_records/{record['id']}", json=payload
                )

        log.info("creating DNS A record %s -> %s", name, ip)
        return await self._request("POST", f"/zones/{zone_id}/dns_records", json=payload)

    async def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    # ---------------------------------------------------------------- SSL (guide §13)

    async def get_ssl_mode(self, zone_id: str) -> str:
        result = await self._request("GET", f"/zones/{zone_id}/settings/ssl")
        return result.get("value", "")

    async def set_ssl_mode(self, zone_id: str, mode: str = "strict") -> str:
        """Set SSL/TLS encryption mode. ``strict`` is Cloudflare's name for Full (strict)."""
        current = await self.get_ssl_mode(zone_id)
        if current == mode:
            return current
        log.info("setting zone SSL mode %s -> %s", current or "unknown", mode)
        result = await self._request(
            "PATCH", f"/zones/{zone_id}/settings/ssl", json={"value": mode}
        )
        return result.get("value", mode)

    async def set_always_use_https(self, zone_id: str, enabled: bool = True) -> None:
        await self._request(
            "PATCH",
            f"/zones/{zone_id}/settings/always_use_https",
            json={"value": "on" if enabled else "off"},
        )

    # ---------------------------------------------------------------- Origin CA (guide §14)

    async def create_origin_certificate(
        self, hostnames: list[str], *, validity_days: int = 5475
    ) -> OriginCertificate:
        """Issue an Origin CA certificate for ``hostnames`` from a locally generated key.

        Cloudflare's Origin CA endpoint historically authenticates with the account-wide
        Origin CA Key rather than a scoped token. Newer tokens carrying SSL and Certificates:
        Edit also work, so we try the token first and fall back to the key when configured.
        """
        csr_pem, key_pem = generate_csr(hostnames)
        payload = {
            "hostnames": hostnames,
            "requested_validity": validity_days,
            "request_type": "origin-rsa",
            "csr": csr_pem,
        }

        try:
            result = await self._request("POST", "/certificates", json=payload)
        except CloudflareError as exc:
            if not self.origin_ca_key:
                raise CloudflareError(
                    "Origin certificate issuance failed. If the API token lacks the "
                    "'SSL and Certificates: Edit' permission at user level, set an "
                    "Origin CA Key in the panel (Cloudflare dashboard -> My Profile -> "
                    f"API Tokens -> Origin CA Key). Original error: {exc}"
                ) from exc
            log.info("retrying Origin CA issuance with the Origin CA Key")
            result = await self._request(
                "POST", "/certificates", json=payload, use_origin_ca_key=True
            )

        return OriginCertificate(
            certificate_pem=result["certificate"],
            private_key_pem=key_pem,
            hostnames=hostnames,
            expires_on=result.get("expires_on"),
        )
