"""Nginx Proxy Manager API client (guide §11, §15, §16, §20).

Everything the guide does by clicking through the NPM admin UI is done here over its REST
API, so adding a service is one call rather than a form. Operations are written to be
reconciling: creating a proxy host that already exists updates it instead of failing.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

log = logging.getLogger("edgekit.npm")

#: Shipped by the NPM image on first boot; the provisioner rotates these immediately.
DEFAULT_EMAIL = "admin@example.com"
DEFAULT_PASSWORD = "changeme"


class NPMError(RuntimeError):
    """An NPM API call failed."""


class NPMAuthError(NPMError):
    """Credentials were rejected."""


@dataclass
class ProxyHostSpec:
    domain: str
    forward_host: str
    forward_port: int
    scheme: str = "http"
    certificate_id: int | None = None
    force_ssl: bool = True
    http2: bool = True
    websockets: bool = True
    block_exploits: bool = True
    hsts: bool = False
    advanced_config: str = ""
    extra_domains: list[str] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        cert = self.certificate_id or 0
        ssl_on = bool(self.certificate_id)
        return {
            "domain_names": [self.domain, *self.extra_domains],
            "forward_scheme": self.scheme,
            "forward_host": self.forward_host,
            "forward_port": int(self.forward_port),
            "certificate_id": cert,
            "ssl_forced": bool(self.force_ssl and ssl_on),
            "http2_support": bool(self.http2 and ssl_on),
            "hsts_enabled": bool(self.hsts and ssl_on),
            "hsts_subdomains": False,
            "block_exploits": bool(self.block_exploits),
            "caching_enabled": False,
            "allow_websocket_upgrade": bool(self.websockets),
            "access_list_id": 0,
            "advanced_config": self.advanced_config,
            "locations": [],
            "meta": {"letsencrypt_agree": False, "dns_challenge": False},
        }


class NPMClient:
    """Async client. Use as an async context manager, or call :meth:`aclose` yourself."""

    def __init__(self, base_url: str, email: str, password: str, *, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self._token: str | None = None
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

    async def __aenter__(self) -> NPMClient:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---------------------------------------------------------------- plumbing

    async def _login(self) -> str:
        response = await self._client.post(
            "/tokens", json={"identity": self.email, "secret": self.password}
        )
        if response.status_code in (401, 403):
            raise NPMAuthError(f"NPM rejected credentials for {self.email}")
        if response.status_code >= 400:
            raise NPMError(f"NPM login failed ({response.status_code}): {response.text[:300]}")
        token = response.json().get("token")
        if not token:
            raise NPMError("NPM login returned no token")
        self._token = token
        return token

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        if self._token is None:
            await self._login()

        headers = {**kwargs.pop("headers", {}), "Authorization": f"Bearer {self._token}"}
        response = await self._client.request(method, path, headers=headers, **kwargs)

        # Tokens are short-lived; transparently re-auth once rather than making callers care.
        if response.status_code == 401:
            await self._login()
            headers["Authorization"] = f"Bearer {self._token}"
            response = await self._client.request(method, path, headers=headers, **kwargs)

        if response.status_code >= 400:
            raise NPMError(
                f"NPM {method} {path} failed ({response.status_code}): {response.text[:500]}"
            )
        if not response.content:
            return None
        return response.json()

    # ---------------------------------------------------------------- health / bootstrap

    async def wait_until_ready(self, attempts: int = 40, delay: float = 3.0) -> None:
        """NPM runs migrations on first boot; the API 502s until they finish."""
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = await self._client.get("/")
                if response.status_code < 500:
                    log.info("NPM API ready after %d attempt(s)", attempt)
                    return
                last = NPMError(f"status {response.status_code}")
            except httpx.HTTPError as exc:
                last = exc
            await asyncio.sleep(delay)
        raise NPMError(f"NPM API did not become ready in {int(attempts * delay)}s: {last}")

    async def bootstrap_admin(
        self, new_email: str, new_password: str, name: str = "edgekit"
    ) -> bool:
        """Rotate the shipped default credentials (guide §11).

        Returns True if the defaults were still in place and got rotated, False if the
        account had already been secured — either way the account ends up usable.
        """
        probe = NPMClient(self.base_url, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        try:
            await probe._login()
        except NPMAuthError:
            log.info("NPM default credentials already rotated")
            await probe.aclose()
            return False
        except NPMError:
            await probe.aclose()
            raise

        try:
            await probe._request(
                "PUT",
                "/users/me",
                json={"name": name, "nickname": name, "email": new_email},
            )
            await probe._request(
                "PUT",
                "/users/me/auth",
                json={
                    "type": "password",
                    "current": DEFAULT_PASSWORD,
                    "secret": new_password,
                },
            )
        finally:
            await probe.aclose()

        # Force the next call on this client to authenticate with the new credentials.
        self.email, self.password, self._token = new_email, new_password, None
        log.info("NPM admin credentials rotated to %s", new_email)
        return True

    async def me(self) -> dict[str, Any]:
        return await self._request("GET", "/users/me")

    # ---------------------------------------------------------------- certificates

    async def list_certificates(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/certificates") or []

    async def find_certificate(self, nice_name: str) -> dict[str, Any] | None:
        for cert in await self.list_certificates():
            if cert.get("nice_name") == nice_name:
                return cert
        return None

    async def upload_custom_certificate(
        self, nice_name: str, certificate_pem: str, key_pem: str
    ) -> int:
        """Create (or replace) a custom certificate and return its NPM id (guide §15).

        NPM has no update-in-place for uploaded certificates, so replacing means creating the
        new record first and deleting the old one only after the upload succeeds — a failed
        upload must never leave the hosts without a certificate.
        """
        existing = await self.find_certificate(nice_name)

        created = await self._request(
            "POST", "/nginx/certificates", json={"provider": "other", "nice_name": nice_name}
        )
        cert_id = created["id"]

        files = {
            "certificate": ("cert.pem", certificate_pem.encode(), "application/x-pem-file"),
            "certificate_key": ("key.pem", key_pem.encode(), "application/x-pem-file"),
        }
        try:
            await self._request("POST", f"/nginx/certificates/{cert_id}/upload", files=files)
        except NPMError:
            await self.delete_certificate(cert_id)
            raise

        if existing and existing["id"] != cert_id:
            # Re-point every host on the old certificate before removing it.
            await self._repoint_hosts(existing["id"], cert_id)
            await self.delete_certificate(existing["id"])

        return cert_id

    async def _repoint_hosts(self, old_id: int, new_id: int) -> None:
        for host in await self.list_proxy_hosts():
            if host.get("certificate_id") == old_id:
                await self._request(
                    "PUT",
                    f"/nginx/proxy-hosts/{host['id']}",
                    json={"certificate_id": new_id},
                )

    async def delete_certificate(self, cert_id: int) -> None:
        await self._request("DELETE", f"/nginx/certificates/{cert_id}")

    # ---------------------------------------------------------------- proxy hosts

    async def list_proxy_hosts(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/proxy-hosts") or []

    async def find_proxy_host(self, domain: str) -> dict[str, Any] | None:
        for host in await self.list_proxy_hosts():
            if domain in (host.get("domain_names") or []):
                return host
        return None

    async def upsert_proxy_host(self, spec: ProxyHostSpec) -> dict[str, Any]:
        """Create the host, or update it in place if the domain is already configured."""
        existing = await self.find_proxy_host(spec.domain)
        if existing:
            log.info("updating existing NPM proxy host for %s (id=%s)", spec.domain, existing["id"])
            return await self._request(
                "PUT", f"/nginx/proxy-hosts/{existing['id']}", json=spec.payload()
            )
        log.info("creating NPM proxy host for %s -> %s:%s", spec.domain, spec.forward_host,
                 spec.forward_port)
        return await self._request("POST", "/nginx/proxy-hosts", json=spec.payload())

    async def delete_proxy_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/nginx/proxy-hosts/{host_id}")

    async def set_proxy_host_enabled(self, host_id: int, enabled: bool) -> None:
        action = "enable" if enabled else "disable"
        await self._request("POST", f"/nginx/proxy-hosts/{host_id}/{action}")
