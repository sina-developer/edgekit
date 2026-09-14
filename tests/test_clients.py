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
    async def test_a_fresh_npm_with_no_seeded_user_gets_one_created(self):
        """NPM >= 2.13 ships with an empty user table; the first admin must be created."""
        created = {"done": False}

        def tokens(request: httpx.Request) -> httpx.Response:
            body = request.read().decode()
            if "me@example.com" in body and created["done"]:
                return httpx.Response(200, json={"token": "new-token"})
            return httpx.Response(400, json={"error": {"message": "Invalid"}})

        def create_user(request: httpx.Request) -> httpx.Response:
            created["done"] = True
            return httpx.Response(201, json={"id": 1, "email": "me@example.com"})

        respx.post(f"{NPM_BASE}/tokens").mock(side_effect=tokens)
        users = respx.post(f"{NPM_BASE}/users").mock(side_effect=create_user)

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            assert await client.bootstrap_admin("me@example.com", "new-password") is True

        payload = json.loads(users.calls[0].request.read())
        assert payload["email"] == "me@example.com"
        assert payload["roles"] == ["admin"]
        assert payload["auth"] == {"type": "password", "secret": "new-password"}

    @respx.mock
    async def test_a_build_ignoring_the_nested_auth_gets_the_password_set_explicitly(self):
        state = {"user": False, "auth": False}

        def tokens(request: httpx.Request) -> httpx.Response:
            if state["auth"]:
                return httpx.Response(200, json={"token": "t"})
            return httpx.Response(400, json={"error": {"message": "Invalid"}})

        def set_auth(request: httpx.Request) -> httpx.Response:
            state["auth"] = True
            return httpx.Response(200, json={})

        respx.post(f"{NPM_BASE}/tokens").mock(side_effect=tokens)
        respx.post(f"{NPM_BASE}/users").mock(
            return_value=httpx.Response(201, json={"id": 7})
        )
        auth = respx.put(f"{NPM_BASE}/users/7/auth").mock(side_effect=set_auth)

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            assert await client.bootstrap_admin("me@example.com", "new-password") is True

        assert auth.called

    @respx.mock
    async def test_user_creation_is_not_attempted_when_defaults_still_work(self):
        """Legacy rotation must take priority; creating a second admin would be wrong."""
        # The configured credentials must fail first, or this is just the re-run case.
        calls = {"n": 0}

        def gated(request: httpx.Request) -> httpx.Response:
            body = request.read().decode()
            if "changeme" in body:
                return httpx.Response(200, json={"token": "default"})
            calls["n"] += 1
            if calls["n"] > 3:
                return httpx.Response(200, json={"token": "new"})
            return httpx.Response(400, json={"error": {"message": "Invalid"}})

        respx.post(f"{NPM_BASE}/tokens").mock(side_effect=gated)
        respx.put(f"{NPM_BASE}/users/me").mock(return_value=httpx.Response(200, json={}))
        respx.put(f"{NPM_BASE}/users/me/auth").mock(return_value=httpx.Response(200, json={}))
        users = respx.post(f"{NPM_BASE}/users")

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            assert await client.bootstrap_admin("me@example.com", "new-password") is True

        assert not users.called, "must rotate the existing admin, not create a second one"

    @respx.mock
    async def test_neither_credential_set_working_raises_rather_than_lying(self):
        """The old code returned False here, silently leaving NPM on admin/changeme."""
        respx.post(f"{NPM_BASE}/tokens").mock(
            return_value=httpx.Response(400, json={"error": {"message": "Invalid"}})
        )
        # An already-initialised NPM refuses unauthenticated user creation.
        respx.post(f"{NPM_BASE}/users").mock(return_value=httpx.Response(403))
        respx.get(f"{NPM_BASE}/").mock(
            return_value=httpx.Response(200, json={"status": "OK", "version": "2.13.1"})
        )

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            with pytest.raises(NPMError) as caught:
                await client.bootstrap_admin("me@example.com", "new-password")

        message = str(caught.value)
        assert "Could not establish an admin account" in message
        # The message must carry enough to diagnose without a second round trip.
        assert "2.13.1" in message
        assert "HTTP 400" in message
        assert "edgekit npm password" in message

    @respx.mock
    async def test_diagnostics_survive_an_unreachable_api_root(self):
        """Gathering diagnostics must not mask the original failure."""
        respx.post(f"{NPM_BASE}/tokens").mock(
            return_value=httpx.Response(400, json={"error": {"message": "Invalid"}})
        )
        respx.post(f"{NPM_BASE}/users").mock(return_value=httpx.Response(403))
        respx.get(f"{NPM_BASE}/").mock(side_effect=httpx.ConnectError("refused"))

        async with NPMClient(NPM_BASE, "me@example.com", "new-password") as client:
            with pytest.raises(NPMError, match="Could not establish an admin account"):
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
async def test_records_pointing_here_get_the_modes_proxy_status():
    """A DNS-only record in front of an Origin certificate is what browsers reject."""
    respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(
            200,
            json=cf_ok([
                {"id": "r1", "name": "example.com", "type": "A",
                 "content": "203.0.113.10", "proxied": False},
                {"id": "r2", "name": "files.example.com", "type": "A",
                 "content": "203.0.113.10", "proxied": True},
                {"id": "r3", "name": "elsewhere.example.com", "type": "A",
                 "content": "198.51.100.7", "proxied": False},
            ]),
        )
    )
    wrong = respx.patch(f"{CF_BASE}/zones/z1/dns_records/r1").mock(
        return_value=httpx.Response(200, json=cf_ok({"id": "r1"}))
    )
    right = respx.patch(f"{CF_BASE}/zones/z1/dns_records/r2")
    other_server = respx.patch(f"{CF_BASE}/zones/z1/dns_records/r3")

    async with CloudflareClient("token") as client:
        changed = await client.reconcile_proxy_status("z1", "203.0.113.10", proxied=True)

    assert changed == ["example.com"]
    assert json.loads(wrong.calls[0].request.read()) == {"proxied": True}
    assert not right.called
    assert not other_server.called, "records for another server are not this edge's to change"


@respx.mock
async def test_only_records_edgekit_created_count_as_its_own():
    """Removal deletes these, so a hand-made record must never match."""
    respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(
        return_value=httpx.Response(
            200,
            json=cf_ok([
                {"id": "r1", "name": "example.com", "comment": "Managed by edgekit"},
                {"id": "r2", "name": "files.example.com", "comment": None},
                {"id": "r3", "name": "mail.example.com", "comment": "added by hand"},
            ]),
        )
    )

    async with CloudflareClient("token") as client:
        assert [r["id"] for r in await client.managed_records("z1")] == ["r1"]


@respx.mock
async def test_letsencrypt_retries_without_legacy_fields_when_npm_refuses_them():
    respx.post(f"{NPM_BASE}/tokens").mock(return_value=httpx.Response(200, json={"token": "t"}))
    create = respx.post(f"{NPM_BASE}/nginx/certificates").mock(
        side_effect=[
            httpx.Response(
                400, json={"error": {"message": "data/meta must NOT have additional properties"}}
            ),
            httpx.Response(201, json={"id": 9, "expires_on": "2026-12-13 10:00:00"}),
        ]
    )

    async with NPMClient(NPM_BASE, "ops@blockey.ir", "pw") as client:
        result = await client.create_letsencrypt_certificate(
            "Let's Encrypt - example.com",
            ["*.example.com", "example.com"],
            dns_provider="cloudflare",
            dns_credentials="dns_cloudflare_api_token=abc",
            email="ops@blockey.ir",
        )

    assert result["id"] == 9
    legacy, current = (json.loads(call.request.read()) for call in create.calls)
    assert legacy["meta"]["letsencrypt_email"] == "ops@blockey.ir"
    assert legacy["meta"]["letsencrypt_agree"] is True
    assert "letsencrypt_email" not in current["meta"]
    assert current["provider"] == "letsencrypt"
    assert current["meta"]["dns_challenge"] is True
    assert current["meta"]["dns_provider_credentials"] == "dns_cloudflare_api_token=abc"


@respx.mock
async def test_a_failed_issuance_is_not_retried_as_a_schema_mismatch():
    respx.post(f"{NPM_BASE}/tokens").mock(return_value=httpx.Response(200, json={"token": "t"}))
    create = respx.post(f"{NPM_BASE}/nginx/certificates").mock(
        return_value=httpx.Response(500, json={"error": {"message": "certbot failed"}})
    )

    async with NPMClient(NPM_BASE, "ops@blockey.ir", "pw") as client:
        with pytest.raises(NPMError) as caught:
            await client.create_letsencrypt_certificate(
                "LE", ["*.example.com", "example.com"], dns_provider="cloudflare",
                dns_credentials="x", email="ops@blockey.ir",
            )

    assert caught.value.status_code == 500
    assert create.call_count == 1


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
async def test_account_owned_tokens_are_accepted_via_the_zones_fallback():
    """/user/tokens/verify rejects account-owned tokens that are otherwise perfectly valid."""
    verify = respx.get(f"{CF_BASE}/user/tokens/verify").mock(
        return_value=httpx.Response(
            401, json={"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]}
        )
    )
    zones = respx.get(f"{CF_BASE}/zones").mock(
        return_value=httpx.Response(200, json=cf_ok([{"id": "z1", "name": "example.com"}]))
    )

    async with CloudflareClient("account-token") as client:
        result = await client.verify_token()

    assert verify.called
    assert zones.called
    assert result["scope"] == "account"


@respx.mock
async def test_a_token_failing_both_checks_is_reported_as_unusable():
    respx.get(f"{CF_BASE}/user/tokens/verify").mock(
        return_value=httpx.Response(
            401, json={"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]}
        )
    )
    respx.get(f"{CF_BASE}/zones").mock(
        return_value=httpx.Response(
            403, json={"success": False, "errors": [{"code": 9109, "message": "Unauthorized"}]}
        )
    )

    async with CloudflareClient("bad") as client:
        with pytest.raises(CloudflareError, match="cannot be used"):
            await client.verify_token()


@respx.mock
async def test_a_non_token_error_is_not_masked_by_the_fallback():
    """A 500 from Cloudflare must surface as itself, not as a credential problem."""
    respx.get(f"{CF_BASE}/user/tokens/verify").mock(
        return_value=httpx.Response(
            500, json={"success": False, "errors": [{"code": 10000, "message": "internal"}]}
        )
    )
    zones = respx.get(f"{CF_BASE}/zones")

    async with CloudflareClient("token") as client:
        with pytest.raises(CloudflareError, match="internal"):
            await client.verify_token()

    assert not zones.called


@respx.mock
async def test_origin_certificate_error_names_the_account_token_limitation():
    respx.post(f"{CF_BASE}/certificates").mock(
        return_value=httpx.Response(
            403, json={"success": False, "errors": [{"code": 1000, "message": "denied"}]}
        )
    )

    async with CloudflareClient("account-token") as client:
        with pytest.raises(CloudflareError, match="Origin CA Key"):
            await client.create_origin_certificate(["example.com"])


class TestZonePermissions:
    """A token that can list zones may still be unable to touch DNS or zone settings."""

    @staticmethod
    def _mock(dns: int = 200, ssl: int = 200, certs: int = 200) -> None:
        def responder(code: int):
            if code == 200:
                return httpx.Response(200, json=cf_ok([]))
            return httpx.Response(
                code, json={"success": False, "errors": [{"code": 9109, "message": "Unauthorized"}]}
            )

        respx.get(f"{CF_BASE}/zones/z1/dns_records").mock(return_value=responder(dns))
        respx.get(f"{CF_BASE}/zones/z1/settings/ssl").mock(return_value=responder(ssl))
        respx.get(f"{CF_BASE}/certificates").mock(return_value=responder(certs))

    @respx.mock
    async def test_a_fully_scoped_token_passes(self):
        self._mock()

        async with CloudflareClient("token") as client:
            report = await client.require_zone_permissions("z1")

        assert all(c.ok for c in report)

    @respx.mock
    async def test_missing_dns_permission_is_named(self):
        self._mock(dns=403)

        async with CloudflareClient("token") as client:
            with pytest.raises(CloudflareError) as caught:
                await client.require_zone_permissions("z1")

        message = str(caught.value)
        assert "DNS records" in message
        assert "DNS:Edit" in message
        assert "Zone:Read alone is not enough" in message

    @respx.mock
    async def test_missing_zone_settings_permission_is_named(self):
        self._mock(ssl=403)

        async with CloudflareClient("token") as client:
            with pytest.raises(CloudflareError, match="Zone Settings:Edit"):
                await client.require_zone_permissions("z1")

    @respx.mock
    async def test_every_missing_required_permission_is_listed_at_once(self):
        self._mock(dns=403, ssl=403)

        async with CloudflareClient("token") as client:
            with pytest.raises(CloudflareError) as caught:
                await client.require_zone_permissions("z1")

        message = str(caught.value)
        assert "DNS:Edit" in message
        assert "Zone Settings:Edit" in message

    @respx.mock
    async def test_origin_certificates_are_optional(self):
        """An account-owned token cannot issue certs, but is otherwise perfectly usable."""
        self._mock(certs=403)

        async with CloudflareClient("token") as client:
            report = await client.require_zone_permissions("z1")

        certs = next(c for c in report if c.label == "Origin certificates")
        assert certs.ok is False
        assert certs.required is False


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


class TestCertificateReplacement:
    """Replacing a certificate must never leave a vhost pointing at a deleted one.

    NPM reports no error for that state: nginx simply refuses the vhost, the handshake for
    that hostname fails, and Cloudflare shows a 525 with no obvious cause.
    """

    @staticmethod
    def _login():
        respx.post(f"{NPM_BASE}/tokens").mock(
            return_value=httpx.Response(200, json={"token": "t0ken"})
        )

    @respx.mock
    async def test_every_duplicate_under_the_label_is_swept_not_just_the_newest(self):
        """A replace that failed half way through leaves more than one record behind."""
        self._login()
        respx.get(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": 3, "nice_name": "Origin"},
                    {"id": 4, "nice_name": "Origin"},
                    {"id": 5, "nice_name": "Other"},
                ],
            )
        )
        respx.post(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json={"id": 9})
        )
        respx.post(f"{NPM_BASE}/nginx/certificates/9/upload").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(return_value=httpx.Response(200, json=[]))
        deleted = []
        respx.delete(url__regex=rf"{NPM_BASE}/nginx/certificates/(?P<cid>\d+)").mock(
            side_effect=lambda request, cid: deleted.append(int(cid))
            or httpx.Response(200, json={})
        )

        async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
            new_id = await client.upload_custom_certificate("Origin", "cert", "key")

        assert new_id == 9
        assert sorted(deleted) == [3, 4], "the other label must be left alone"

    @respx.mock
    async def test_hosts_are_moved_onto_the_new_certificate_before_the_old_one_goes(self):
        self._login()
        respx.get(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json=[{"id": 3, "nice_name": "Origin"}])
        )
        respx.post(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json={"id": 9})
        )
        respx.post(f"{NPM_BASE}/nginx/certificates/9/upload").mock(
            return_value=httpx.Response(200, json={})
        )
        moved: list[int] = []
        hosts = [{"id": 1, "certificate_id": 3, "domain_names": ["a.example.com"]}]

        def list_hosts(request):
            return httpx.Response(200, json=hosts)

        def move(request, hid):
            moved.append(int(hid))
            hosts[0]["certificate_id"] = json.loads(request.content)["certificate_id"]
            return httpx.Response(200, json=hosts[0])

        respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(side_effect=list_hosts)
        respx.put(url__regex=rf"{NPM_BASE}/nginx/proxy-hosts/(?P<hid>\d+)").mock(side_effect=move)
        deleted = []
        respx.delete(url__regex=rf"{NPM_BASE}/nginx/certificates/(?P<cid>\d+)").mock(
            side_effect=lambda request, cid: deleted.append(int(cid))
            or httpx.Response(200, json={})
        )

        async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
            await client.upload_custom_certificate("Origin", "cert", "key")

        assert moved == [1]
        assert deleted == [3]

    @respx.mock
    async def test_an_old_certificate_still_in_use_is_kept(self):
        """If a host could not be moved, deleting its certificate would break TLS for it."""
        self._login()
        respx.get(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json=[{"id": 3, "nice_name": "Origin"}])
        )
        respx.post(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json={"id": 9})
        )
        respx.post(f"{NPM_BASE}/nginx/certificates/9/upload").mock(
            return_value=httpx.Response(200, json={})
        )
        # The host list never changes: the PUT "succeeds" but the host stays on cert 3.
        respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(
            return_value=httpx.Response(
                200, json=[{"id": 1, "certificate_id": 3, "domain_names": ["a.example.com"]}]
            )
        )
        respx.put(url__regex=rf"{NPM_BASE}/nginx/proxy-hosts/(?P<hid>\d+)").mock(
            return_value=httpx.Response(200, json={})
        )
        delete = respx.delete(url__regex=rf"{NPM_BASE}/nginx/certificates/(?P<cid>\d+)").mock(
            return_value=httpx.Response(200, json={})
        )

        async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
            await client.upload_custom_certificate("Origin", "cert", "key")

        assert delete.call_count == 0

    @respx.mock
    async def test_a_failed_upload_removes_the_half_made_record(self):
        self._login()
        respx.get(f"{NPM_BASE}/nginx/certificates").mock(return_value=httpx.Response(200, json=[]))
        respx.post(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json={"id": 9})
        )
        respx.post(f"{NPM_BASE}/nginx/certificates/9/upload").mock(
            return_value=httpx.Response(400, text="bad key")
        )
        delete = respx.delete(f"{NPM_BASE}/nginx/certificates/9").mock(
            return_value=httpx.Response(200, json={})
        )

        async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
            with pytest.raises(NPMError):
                await client.upload_custom_certificate("Origin", "cert", "key")

        assert delete.call_count == 1

    @respx.mock
    async def test_one_host_that_will_not_move_does_not_strand_the_others(self):
        self._login()
        respx.get(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json=[{"id": 3, "nice_name": "Origin"}])
        )
        respx.post(f"{NPM_BASE}/nginx/certificates").mock(
            return_value=httpx.Response(200, json={"id": 9})
        )
        respx.post(f"{NPM_BASE}/nginx/certificates/9/upload").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{NPM_BASE}/nginx/proxy-hosts").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": 1, "certificate_id": 3, "domain_names": ["a.example.com"]},
                    {"id": 2, "certificate_id": 3, "domain_names": ["b.example.com"]},
                ],
            )
        )
        attempted: list[int] = []

        def move(request, hid):
            attempted.append(int(hid))
            if int(hid) == 1:
                return httpx.Response(500, text="nope")
            return httpx.Response(200, json={})

        respx.put(url__regex=rf"{NPM_BASE}/nginx/proxy-hosts/(?P<hid>\d+)").mock(side_effect=move)

        async with NPMClient(NPM_BASE, "a@b.c", "pw") as client:
            with pytest.raises(NPMError, match="a.example.com"):
                await client.upload_custom_certificate("Origin", "cert", "key")

        assert attempted == [1, 2], "the second host must still be attempted"
