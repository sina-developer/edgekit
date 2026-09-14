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

#: Stamped on every record edgekit creates, so removal can tell its records from the
#: operator's own. Records edgekit merely found already correct keep their own comment.
MANAGED_COMMENT = "Managed by edgekit"


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
class Capability:
    """One permission edgekit needs, and whether this token actually has it."""

    label: str
    permission: str
    ok: bool
    required: bool = True
    detail: str = ""


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

    #: Cloudflare's "this token is not usable here" family.
    _BAD_TOKEN_CODES = (1000, 6003, 9109, 9106)

    async def verify_token(self) -> dict[str, Any]:
        """Confirm the token works, without assuming which kind of token it is.

        ``/user/tokens/verify`` only accepts *user* tokens (My Profile -> API Tokens).
        An **account-owned** token — created from an account's own API Tokens page — is
        rejected there with code 1000 despite being perfectly valid for zones and DNS. So a
        failure at that endpoint proves nothing on its own, and we fall back to exercising
        the permission edgekit actually needs: listing zones.
        """
        try:
            return await self._request("GET", "/user/tokens/verify")
        except CloudflareError as exc:
            if not any(e.get("code") in self._BAD_TOKEN_CODES for e in exc.errors):
                raise

            try:
                await self._request("GET", "/zones", params={"per_page": 1})
            except CloudflareError as zone_exc:
                raise CloudflareError(
                    "Cloudflare rejected this API token for both token verification and "
                    "listing zones, so it cannot be used.\n"
                    "  1. Use the token *secret* shown once at creation — not the token ID, "
                    "and not the Global API Key.\n"
                    "  2. A truncated or line-wrapped paste fails exactly this way; create a "
                    "fresh token and copy it in one go.\n"
                    "  3. It needs Zone:Read, DNS:Edit, Zone Settings:Edit and SSL and "
                    "Certificates:Edit, with Zone Resources including this zone.\n"
                    "  4. Check the token is Active and any IP-address filter on it allows "
                    "this server.\n"
                    f"Zone listing said: {zone_exc}"
                ) from exc

            log.info(
                "token is not a user token (account-owned); verified by listing zones instead"
            )
            return {"status": "active", "scope": "account"}

    async def check_zone_permissions(self, zone_id: str) -> list[Capability]:
        """Exercise each permission edgekit needs, against this specific zone.

        Listing zones only proves Zone:Read. A token can pass that and still be unable to
        touch DNS records or zone settings, which then fails much later during provisioning
        with an opaque 403. Probing each capability up front turns that into a precise list
        of what to tick in the Cloudflare UI.
        """
        probes = (
            ("DNS records", "DNS:Edit", f"/zones/{zone_id}/dns_records", {"per_page": 1}, True),
            ("SSL/TLS mode", "Zone Settings:Edit", f"/zones/{zone_id}/settings/ssl", None, True),
            ("Origin certificates", "SSL and Certificates:Edit", "/certificates",
             {"zone_id": zone_id}, False),
        )

        results: list[Capability] = []
        for label, permission, path, params, required in probes:
            try:
                await self._request("GET", path, params=params or {})
            except CloudflareError as exc:
                results.append(Capability(label, permission, False, required, str(exc)))
            else:
                results.append(Capability(label, permission, True, required))
        return results

    async def require_zone_permissions(self, zone_id: str) -> list[Capability]:
        """Raise unless every *required* capability is available. Returns the full report."""
        report = await self.check_zone_permissions(zone_id)
        missing = [c for c in report if c.required and not c.ok]
        if missing:
            lines = "\n".join(f"  - {c.label} — needs {c.permission}" for c in missing)
            raise CloudflareError(
                "This Cloudflare token can see the zone but lacks the permissions edgekit "
                f"needs:\n{lines}\n"
                "Edit the token in the Cloudflare dashboard (the same page you created it "
                "on) and add those permissions, with Zone Resources set to include this "
                "zone. Zone:Read alone is not enough.\n"
                "Then re-run `edgekit cloudflare token --zone <zone>` or `edgekit provision`."
            )
        return report

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
            "comment": MANAGED_COMMENT,
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

    async def managed_records(self, zone_id: str) -> list[dict]:
        """Every record edgekit created in the zone, whatever its type."""
        records = await self._request(
            "GET", f"/zones/{zone_id}/dns_records", params={"per_page": 1000}
        )
        return [r for r in records or [] if r.get("comment") == MANAGED_COMMENT]

    async def list_a_records(self, zone_id: str) -> list[dict]:
        return (
            await self._request(
                "GET", f"/zones/{zone_id}/dns_records", params={"type": "A", "per_page": 1000}
            )
            or []
        )

    async def reconcile_proxy_status(self, zone_id: str, ip: str, *, proxied: bool) -> list[str]:
        """Give every A record pointing at ``ip`` the proxy status ``proxied``.

        Not just the records edgekit created: a hostname added by hand in the dashboard with
        the wrong cloud breaks TLS exactly as badly. DNS only in front of an Origin
        certificate hands browsers a certificate only Cloudflare trusts. Returns the names
        that were changed.
        """
        changed: list[str] = []
        for record in await self.list_a_records(zone_id):
            if record.get("content") != ip or bool(record.get("proxied")) == proxied:
                continue
            if proxied and record.get("proxiable") is False:
                log.warning("DNS record %s cannot be proxied; leaving it", record.get("name"))
                continue
            log.info("setting DNS record %s proxied=%s", record.get("name"), proxied)
            await self._request(
                "PATCH",
                f"/zones/{zone_id}/dns_records/{record['id']}",
                json={"proxied": proxied},
            )
            changed.append(record.get("name", record["id"]))
        return changed

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
                    "Could not issue the origin certificate. Cloudflare's Origin CA endpoint "
                    "is user-scoped, so an account-owned token cannot drive it even when it "
                    "manages DNS for this zone perfectly well.\n"
                    "Fix it with either:\n"
                    "  - the Origin CA Key: Cloudflare dashboard -> My Profile -> API Tokens "
                    "-> Origin CA Key -> View, then `edgekit cloudflare token "
                    "--origin-ca-key <key>`; or\n"
                    "  - a *user* token (My Profile -> API Tokens) carrying 'SSL and "
                    "Certificates: Edit'.\n"
                    "Everything else (DNS, SSL mode) keeps working without this — you can "
                    "also paste a certificate by hand under Settings -> Origin certificate.\n"
                    f"Original error: {exc}"
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
