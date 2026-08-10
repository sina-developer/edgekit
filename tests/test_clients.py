"""NPM and Cloudflare client behaviour, against mocked HTTP."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from edgekit.services.cloudflare import (
    CloudflareClient,
    CloudflareError,
    certificate_expiry,
    generate_csr,
)
from edgekit.services.npm import NPMAuthError, NPMClient, NPMError, ProxyHostSpec

NPM_BASE = "http://127.0.0.1:8181/api"
CF_BASE = "https://api.cloudflare.com/client/v4"


def cf_ok(result):
    return {"success": True, "errors": [], "messages": [], "result": result}


# ---------------------------------------------------------------------- NPM


class TestProxyHostSpec:
    def test_ssl_options_are_forced_off_without_a_certificate(self):
        payload = ProxyHostSpec(
            domain="a.example.com", forward_host="10.50.0.2", forward_port=3001,
            certificate_id=None, force_ssl=True, http2=True,
        ).payload()

        assert payload["certificate_id"] == 0
        assert payload["ssl_forced"] is False, "forcing SSL with no cert makes the host unreachable"
        assert payload["http2_support"] is False

    def test_ssl_options_apply_with_a_certificate(self):
        payload = ProxyHostSpec(
            domain="a.example.com", forward_host="10.50.0.2", forward_port=3001,
            certificate_id=7,
        ).payload()

        assert payload["certificate_id"] == 7
        assert payload["ssl_forced"] is True
        assert payload["http2_support"] is True
        assert payload["domain_names"] == ["a.example.com"]
        assert payload["forward_port"] == 3001


@respx.mock
async def test_npm_logs_in_once_and_reuses_the_token():
    login = respx.post(f"{NPM_BASE}/tokens").mock(
        return_value=httpx.Response(200, json={"token": "t0ken"})
    )
    hosts = respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(
        return_value=httpx.Response(200, json=[])
    )

    async with NPMClient(NPM_BASE, "admin@example.com", "pw") as client:
        await client.list_proxy_hosts()
        await client.list_proxy_hosts()

    assert login.call_count == 1
    assert hosts.call_count == 2
    assert hosts.calls[0].request.headers["Authorization"] == "Bearer t0ken"


@respx.mock
async def test_npm_reauthenticates_after_a_401():
    respx.post(f"{NPM_BASE}/tokens").mock(
        side_effect=[
            httpx.Response(200, json={"token": "old"}),
            httpx.Response(200, json={"token": "new"}),
        ]
    )
    hosts = respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json=[{"id": 1}])]
    )

    async with NPMClient(NPM_BASE, "admin@example.com", "pw") as client:
        assert await client.list_proxy_hosts() == [{"id": 1}]

    assert hosts.calls[1].request.headers["Authorization"] == "Bearer new"


@respx.mock
async def test_npm_bad_credentials_raise_auth_error():
    respx.post(f"{NPM_BASE}/tokens").mock(return_value=httpx.Response(401))

    async with NPMClient(NPM_BASE, "admin@example.com", "wrong") as client:
        with pytest.raises(NPMAuthError):
            await client.list_proxy_hosts()


@respx.mock
async def test_npm_reports_a_400_as_an_auth_failure():
    """NPM answers bad credentials on /tokens with 400, not 401."""
    respx.post(f"{NPM_BASE}/tokens").mock(
        return_value=httpx.Response(
            400, json={"error": {"code": 400, "message": "Invalid email or password"}}
        )
    )

    async with NPMClient(NPM_BASE, "admin@example.com", "wrong") as client:
        with pytest.raises(NPMAuthError):
            await client.list_proxy_hosts()


class TestBootstrapAdmin:
    """Guide §11. The dangerous failure is concluding 'already secured' when it is not."""

    @pytest.fixture(autouse=True)
    def _no_sleeping(self, monkeypatch):
        async def instant(_seconds):
            return None

        monkeypatch.setattr("edgekit.services.npm.asyncio.sleep", instant)

    @respx.mock
    async def test_refuses_to_keep_the_shipped_defaults(self):
        async with NPMClient(NPM_BASE, "admin@example.com", "changeme") as client:
            with pytest.raises(NPMError, match="default credentials"):
                await client.bootstrap_admin("admin@example.com", "changeme")

    @respx.mock
    async def test_already_rotated_is_a_no_op(self):
        respx.post(f"{NPM_BASE}/tokens").mock(
            return_value=httpx.Response(200, json={"token": "t"})
        )

        async with NPMClient(NPM_BASE, "me@example.com", "good-password") as client:
            assert await client.bootstrap_admin("me@example.com", "good-password") is False

    @respx.mock
    async def test_defaults_seeded_late_are_still_rotated(self):
        """NPM's API answers before its first-boot migrations seed the admin user."""
        calls = {"n": 0}

        def tokens(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            body = request.read().decode()
            if "changeme" in body:
                # The seed lands on the fourth attempt.
                if calls["n"] < 5:
                    return httpx.Response(400, json={"error": {"message": "Invalid"}})
                return httpx.Response(200, json={"token": "default-token"})
            # The new credentials only work once the rotation has happened.
            if calls["n"] > 6:
                return httpx.Response(200, json={"token": "new-token"})
            return httpx.Response(400, json={"error": {"message": "Invalid"}})

        respx.post(f"{NPM_BASE}/tokens").mock(side_effect=tokens)
        respx.put(f"{NPM_BASE}/users/me").mock(return_value=httpx.Response(200, json={}))
        auth = respx.put(f"{NPM_BASE}/users/me/auth").mock(
            return_value=httpx.Response(200, json={})
        )

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            assert await client.bootstrap_admin("me@example.com", "new-password") is True

        assert auth.called
        assert client.password == "new-password"

    @respx.mock
    async def test_neither_credential_set_working_raises_rather_than_lying(self):
        """The old code returned False here, silently leaving NPM on admin/changeme."""
        respx.post(f"{NPM_BASE}/tokens").mock(
            return_value=httpx.Response(400, json={"error": {"message": "Invalid"}})
        )

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            with pytest.raises(NPMError, match="rejected both"):
                await client.bootstrap_admin("me@example.com", "new-password")

    @respx.mock
    async def test_a_rotation_that_does_not_take_effect_is_reported(self):
        def tokens(request: httpx.Request) -> httpx.Response:
            if "changeme" in request.read().decode():
                return httpx.Response(200, json={"token": "default-token"})
            return httpx.Response(400, json={"error": {"message": "Invalid"}})

        respx.post(f"{NPM_BASE}/tokens").mock(side_effect=tokens)
        respx.put(f"{NPM_BASE}/users/me").mock(return_value=httpx.Response(200, json={}))
        respx.put(f"{NPM_BASE}/users/me/auth").mock(return_value=httpx.Response(200, json={}))

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            with pytest.raises(NPMError, match="then rejected"):
                await client.bootstrap_admin("me@example.com", "new-password")


@respx.mock
async def test_upsert_updates_an_existing_domain_instead_of_duplicating_it():
    respx.post(f"{NPM_BASE}/tokens").mock(return_value=httpx.Response(200, json={"token": "t"}))
    respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(
        return_value=httpx.Response(200, json=[{"id": 9, "domain_names": ["a.example.com"]}])
    )
    update = respx.put(f"{NPM_BASE}/nginx/proxy-hosts/9").mock(
        return_value=httpx.Response(200, json={"id": 9})
    )
    create = respx.post(f"{NPM_BASE}/nginx/proxy-hosts")

    async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
        result = await client.upsert_proxy_host(
            ProxyHostSpec(domain="a.example.com", forward_host="10.50.0.2", forward_port=80)
        )

    assert result["id"] == 9
    assert update.called
    assert not create.called


@respx.mock
async def test_failed_certificate_upload_removes_the_orphan_record():
    """A half-created certificate must not linger and shadow the real one."""
    respx.post(f"{NPM_BASE}/tokens").mock(return_value=httpx.Response(200, json={"token": "t"}))
    respx.get(f"{NPM_BASE}/nginx/certificates").mock(return_value=httpx.Response(200, json=[]))
    respx.post(f"{NPM_BASE}/nginx/certificates").mock(
        return_value=httpx.Response(201, json={"id": 42})
    )
    respx.post(f"{NPM_BASE}/nginx/certificates/42/upload").mock(
        return_value=httpx.Response(400, text="bad certificate")
    )
    delete = respx.delete(f"{NPM_BASE}/nginx/certificates/42").mock(
        return_value=httpx.Response(200, json=True)
    )

    async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
        with pytest.raises(NPMError):
            await client.upload_custom_certificate("test", "cert", "key")

    assert delete.called


# ---------------------------------------------------------------------- Cloudflare


def test_csr_covers_every_hostname():
    from cryptography import x509

    csr_pem, key_pem = generate_csr(["*.example.com", "example.com"])
    assert "BEGIN CERTIFICATE REQUEST" in csr_pem
    assert "PRIVATE KEY" in key_pem

    csr = x509.load_pem_x509_csr(csr_pem.encode())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["*.example.com", "example.com"]


def test_csr_requires_a_hostname():
    with pytest.raises(ValueError):
        generate_csr([])


def test_certificate_expiry_of_garbage_is_none():
    assert certificate_expiry("not a certificate") is None


@respx.mock
async def test_dns_record_is_created_when_absent():
    respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(200, json=cf_ok([]))
    )
    create = respx.post(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(200, json=cf_ok({"id": "rec1"}))
    )

    async with CloudflareClient("token") as client:
        record = await client.upsert_a_record("z1", "a.example.com", "203.0.113.10")

    assert record["id"] == "rec1"
    body = json.loads(create.calls[0].request.read())
    assert body["type"] == "A"
    assert body["name"] == "a.example.com"
    assert body["content"] == "203.0.113.10"
    assert body["proxied"] is True
    assert body["ttl"] == 1, "proxied records only accept the automatic TTL"


@respx.mock
async def test_matching_dns_record_is_left_alone():
    """Re-running provisioning must not churn Cloudflare state."""
    respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(
            200,
            json=cf_ok([
                {"id": "rec1", "type": "A", "content": "203.0.113.10", "proxied": True}
            ]),
        )
    )
    update = respx.put(f"{CF_BASE}/zones/z1/dns_records/rec1")
    create = respx.post(f"{CF_BASE}/zones/z1/dns_records")

    async with CloudflareClient("token") as client:
        await client.upsert_a_record("z1", "a.example.com", "203.0.113.10")

    assert not update.called
    assert not create.called


@respx.mock
async def test_stale_dns_record_is_updated():
    respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(
            200,
            json=cf_ok([
                {"id": "rec1", "type": "A", "content": "198.51.100.1", "proxied": True}
            ]),
        )
    )
    update = respx.put(f"{CF_BASE}/zones/z1/dns_records/rec1").mock(
        return_value=httpx.Response(200, json=cf_ok({"id": "rec1"}))
    )

    async with CloudflareClient("token") as client:
        await client.upsert_a_record("z1", "a.example.com", "203.0.113.10")

    assert update.called


@respx.mock
async def test_ssl_mode_is_not_rewritten_when_already_correct():
    respx.get(f"{CF_BASE}/zones/z1/settings/ssl").mock(
        return_value=httpx.Response(200, json=cf_ok({"value": "strict"}))
    )
    patch = respx.patch(f"{CF_BASE}/zones/z1/settings/ssl")

    async with CloudflareClient("token") as client:
        assert await client.set_ssl_mode("z1", "strict") == "strict"

    assert not patch.called


@respx.mock
async def test_api_errors_are_reported_with_cloudflares_own_message():
    respx.get(f"{CF_BASE}/zones").mock(
        return_value=httpx.Response(
            403,
            json={"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]},
        )
    )

    async with CloudflareClient("bad") as client:
        with pytest.raises(CloudflareError, match="Invalid access token"):
            await client.get_zone_id("example.com")


@respx.mock
async def test_unknown_zone_gives_an_actionable_error():
    respx.get(f"{CF_BASE}/zones").mock(return_value=httpx.Response(200, json=cf_ok([])))

    async with CloudflareClient("token") as client:
        with pytest.raises(CloudflareError, match="Zone:Read"):
            await client.get_zone_id("example.com")


@respx.mock
async def test_origin_certificate_sends_a_csr_and_keeps_the_key_local():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(
            200,
            json=cf_ok(
                {
                    "certificate": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                    "expires_on": "2040-01-01T00:00:00Z",
                }
            ),
        )

    respx.post(f"{CF_BASE}/certificates").mock(side_effect=handler)

    async with CloudflareClient("token") as client:
        cert = await client.create_origin_certificate(["*.example.com", "example.com"])

    assert "BEGIN CERTIFICATE REQUEST" in captured["csr"]
    assert captured["request_type"] == "origin-rsa"
    assert captured["hostnames"] == ["*.example.com", "example.com"]
    # The private key is generated locally and is never part of the request.
    assert "PRIVATE KEY" not in captured["csr"]
    assert "PRIVATE KEY" in cert.private_key_pem


@respx.mock
async def test_origin_certificate_falls_back_to_the_origin_ca_key():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(request.headers))
        if len(calls) == 1:
            return httpx.Response(
                403, json={"success": False, "errors": [{"code": 1, "message": "denied"}]}
            )
        return httpx.Response(200, json=cf_ok({"certificate": "cert", "expires_on": None}))

    respx.post(f"{CF_BASE}/certificates").mock(side_effect=handler)

    async with CloudflareClient("token", origin_ca_key="ca-key") as client:
        await client.create_origin_certificate(["example.com"])

    assert "authorization" in calls[0]
    assert calls[1]["x-auth-user-service-key"] == "ca-key"


@respx.mock
async def test_origin_certificate_without_a_ca_key_explains_the_permission():
    respx.post(f"{CF_BASE}/certificates").mock(
        return_value=httpx.Response(
            403, json={"success": False, "errors": [{"code": 1, "message": "denied"}]}
        )
    )

    async with CloudflareClient("token") as client:
        with pytest.raises(CloudflareError, match="SSL and Certificates"):
            await client.create_origin_certificate(["example.com"])
