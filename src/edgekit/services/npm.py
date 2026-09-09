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

#: The fields NPM accepts on a proxy-host update — used to replay a snapshot on rollback.
WRITABLE_HOST_FIELDS = (
    "domain_names",
    "forward_scheme",
    "forward_host",
    "forward_port",
    "certificate_id",
    "ssl_forced",
    "http2_support",
    "hsts_enabled",
    "hsts_subdomains",
    "block_exploits",
    "caching_enabled",
    "allow_websocket_upgrade",
    "access_list_id",
    "advanced_config",
    "locations",
)


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
        # NPM answers bad credentials on /tokens with 400 ("Invalid email or password"),
        # not 401. Treating 400 as a transport error here would turn a wrong password into
        # an unrecoverable provisioning failure instead of something callers can handle.
        if response.status_code in (400, 401, 403):
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
        """Wait for the HTTP listener. See :meth:`wait_for_login` for the stronger check.

        NPM's express app starts answering well before its first-boot migrations have seeded
        the default admin user, so a 200 here does *not* mean the API is usable yet.
        """
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = await self._client.get("/")
                if response.status_code < 500:
                    log.info("NPM API listening after %d attempt(s)", attempt)
                    return
                last = NPMError(f"status {response.status_code}")
            except httpx.HTTPError as exc:
                last = exc
            await asyncio.sleep(delay)
        raise NPMError(f"NPM API did not become ready in {int(attempts * delay)}s: {last}")

    async def server_info(self) -> dict[str, Any]:
        """The unauthenticated API root, which reports the running NPM version."""
        try:
            response = await self._client.get("/")
            return response.json() if response.content else {}
        except (httpx.HTTPError, ValueError):
            return {}

    async def login_probe(self, email: str, password: str) -> tuple[int, str]:
        """Raw login attempt, returning ``(status_code, body)`` for diagnostics."""
        try:
            response = await self._client.post(
                "/tokens", json={"identity": email, "secret": password}
            )
        except httpx.HTTPError as exc:
            return 0, str(exc)
        return response.status_code, response.text[:300]

    async def _try_login(self) -> bool:
        """Attempt a login, distinguishing 'wrong credentials' from 'not ready yet'."""
        try:
            await self._login()
        except NPMAuthError:
            return False
        return True

    async def wait_for_login(self, attempts: int = 20, delay: float = 3.0) -> bool:
        """Poll until these credentials are accepted or definitively rejected.

        Returns True on success, False if the credentials were rejected on every attempt.
        Transport-level failures keep retrying; an auth rejection is retried too, because on
        a cold start the user table is seeded a few seconds after the API starts answering.
        """
        for attempt in range(1, attempts + 1):
            try:
                if await self._try_login():
                    return True
            except NPMError as exc:
                log.debug("NPM login attempt %d failed: %s", attempt, exc)
            if attempt < attempts:
                await asyncio.sleep(delay)
        return False

    async def create_initial_user(
        self, email: str, password: str, name: str = "edgekit"
    ) -> bool:
        """Create the first admin account on an NPM that shipped without one.

        Versions from 2.13 onwards no longer seed admin@example.com/changeme; a fresh
        install has an empty user table and expects the first account to be created through
        the setup flow. NPM permits that creation unauthenticated *only* while no user
        exists, so this is safe to attempt: on an already-initialised instance it is refused
        and we fall through to reporting the real problem.
        """
        payload = {
            "name": name,
            "nickname": name,
            "email": email,
            "roles": ["admin"],
            "is_disabled": False,
            "auth": {"type": "password", "secret": password},
        }
        try:
            response = await self._client.post("/users", json=payload)
        except httpx.HTTPError as exc:
            log.debug("initial user creation failed at the transport level: %s", exc)
            return False

        if response.status_code >= 400:
            log.debug(
                "NPM refused unauthenticated user creation (%s): %s",
                response.status_code,
                response.text[:200],
            )
            return False

        log.info("created the initial NPM admin account %s", email)
        self.email, self.password, self._token = email, password, None
        if await self.wait_for_login(attempts=5, delay=2.0):
            return True

        # Some builds create the account but ignore the nested auth block; set it explicitly.
        try:
            user_id = response.json().get("id")
        except ValueError:
            user_id = None
        if user_id:
            try:
                await self._client.put(
                    f"/users/{user_id}/auth", json={"type": "password", "secret": password}
                )
            except httpx.HTTPError:
                return False
            self._token = None
            return await self.wait_for_login(attempts=5, delay=2.0)
        return False

    async def bootstrap_admin(
        self, new_email: str, new_password: str, name: str = "edgekit"
    ) -> bool:
        """Ensure the admin account exists and uses our credentials (guide §11).

        Handles all three states an NPM instance can be in:
          1. already using our credentials (a re-run) — nothing to do;
          2. still on the shipped defaults (NPM < 2.13) — rotate them;
          3. freshly installed with no user at all (NPM >= 2.13) — create the first admin.

        Raises if none apply, because returning quietly could leave a reachable proxy
        manager on default or unknown credentials.
        """
        if (new_email, new_password) == (DEFAULT_EMAIL, DEFAULT_PASSWORD):
            raise NPMError(
                "Refusing to configure Nginx Proxy Manager with its default credentials. "
                "Choose a different admin password."
            )

        # 1. Already bootstrapped? The common case on a re-run.
        if await self.wait_for_login(attempts=3, delay=2.0):
            log.info("NPM already accepts the configured credentials")
            return False

        # 2. Legacy images seed admin@example.com/changeme, sometimes a few seconds after
        #    the API starts answering.
        probe = NPMClient(self.base_url, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        try:
            if await probe.wait_for_login(attempts=6, delay=2.0):
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
                self.email, self.password, self._token = new_email, new_password, None
                if not await self.wait_for_login(attempts=5, delay=2.0):
                    raise NPMError(
                        "Rotated the NPM admin credentials, but the new ones were then "
                        "rejected. Check `docker logs nginx-proxy-manager --tail 100`."
                    )
                log.info("NPM admin credentials rotated to %s", new_email)
                return True
        finally:
            await probe.aclose()

        # 3. No default account: this build expects the first admin to be created.
        if await self.create_initial_user(new_email, new_password, name):
            return True

        info = await self.server_info()
        version = info.get("version") or info.get("status") or "unknown"
        status, body = await self.login_probe(new_email, new_password)
        raise NPMError(
            "Could not establish an admin account in Nginx Proxy Manager.\n"
            f"  NPM version: {version}\n"
            f"  Login as {new_email} returned HTTP {status}: {body}\n"
            "An account already exists with a password edgekit does not know.\n"
            "Either tell edgekit the real password:\n"
            "  edgekit npm password\n"
            "or wipe NPM and start clean (destroys its config, keeps edgekit's records):\n"
            "  edgekit npm reset && edgekit provision"
        )

    async def me(self) -> dict[str, Any]:
        return await self._request("GET", "/users/me")

    # ---------------------------------------------------------------- certificates

    async def list_certificates(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/certificates") or []

    async def find_certificate(self, nice_name: str) -> dict[str, Any] | None:
        certificates = await self.find_certificates(nice_name)
        return certificates[0] if certificates else None

    async def find_certificates(self, nice_name: str) -> list[dict[str, Any]]:
        """Every record under this label. More than one means an earlier replace half-failed."""
        return [c for c in await self.list_certificates() if c.get("nice_name") == nice_name]

    async def certificate_exists(self, cert_id: int) -> bool:
        """Whether NPM still holds this record — false after an `npm reset` wiped its data."""
        return any(int(c.get("id", 0)) == int(cert_id) for c in await self.list_certificates())

    async def upload_custom_certificate(
        self, nice_name: str, certificate_pem: str, key_pem: str
    ) -> int:
        """Create (or replace) a custom certificate and return its NPM id (guide §15).

        NPM has no update-in-place for uploaded certificates, so replacing means creating the
        new record first and deleting the old one only after the upload succeeds — a failed
        upload must never leave the hosts without a certificate.

        Superseded records are removed only once nothing points at them any more. A vhost
        left referencing a deleted certificate is not a visible NPM error: nginx keeps a
        configuration naming a file that is gone, the TLS handshake for that hostname aborts,
        and Cloudflare reports it as a 525 that looks nothing like its cause.
        """
        superseded = await self.find_certificates(nice_name)

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

        # Sweep every record under this label, not just the newest: a replace that failed
        # half way through leaves duplicates behind, and each one is a certificate some host
        # may still be pointing at.
        for old in superseded:
            old_id = int(old["id"])
            if old_id == cert_id:
                continue
            await self._repoint_hosts(old_id, cert_id)

        for old in superseded:
            old_id = int(old["id"])
            if old_id == cert_id:
                continue
            if await self._hosts_using(old_id):
                log.warning(
                    "leaving NPM certificate %s in place: proxy hosts still reference it",
                    old_id,
                )
                continue
            await self.delete_certificate(old_id)

        return cert_id

    async def _hosts_using(self, cert_id: int) -> list[dict[str, Any]]:
        return [
            host
            for host in await self.list_proxy_hosts()
            if int(host.get("certificate_id") or 0) == int(cert_id)
        ]

    async def _repoint_hosts(self, old_id: int, new_id: int) -> None:
        """Move every host off ``old_id``. One failure must not abandon the rest."""
        failures: list[str] = []
        for host in await self._hosts_using(old_id):
            try:
                await self._request(
                    "PUT",
                    f"/nginx/proxy-hosts/{host['id']}",
                    json={"certificate_id": new_id},
                )
            except NPMError as exc:
                domain = (host.get("domain_names") or ["?"])[0]
                failures.append(f"{domain}: {exc}")
                log.error("could not re-point %s onto certificate %s: %s", domain, new_id, exc)
        if failures:
            raise NPMError(
                "Some proxy hosts could not be moved onto the new certificate: "
                + "; ".join(failures)
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

    async def restore_proxy_host(self, host_id: int, snapshot: dict[str, Any]) -> Any:
        """Put a proxy host back the way ``snapshot`` found it.

        Only the writable fields are sent: a GET body also carries ids and timestamps NPM
        rejects on the way back in.
        """
        payload = {k: snapshot[k] for k in WRITABLE_HOST_FIELDS if k in snapshot}
        return await self._request("PUT", f"/nginx/proxy-hosts/{host_id}", json=payload)

    async def delete_proxy_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/nginx/proxy-hosts/{host_id}")

    async def set_proxy_host_enabled(self, host_id: int, enabled: bool) -> None:
        action = "enable" if enabled else "disable"
        await self._request("POST", f"/nginx/proxy-hosts/{host_id}/{action}")
