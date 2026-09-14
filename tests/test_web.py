"""Panel behaviour: authentication, CSRF, and the security boundaries around them."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from edgekit import __version__, jobs
from edgekit.db import session_scope
from edgekit.models import User
from edgekit.security import hash_password
from edgekit.web import deps
from edgekit.web.app import create_app

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def client(clean_db, config, fake_wg):
    with session_scope() as session:
        session.add(
            User(
                username="admin",
                password_hash=hash_password(PASSWORD),
                must_change_password=False,
            )
        )

    app = create_app(config)
    # follow_redirects stays off so the tests can assert on the redirects themselves.
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def auth_client(client):
    response = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 303, response.text
    return client


class TestAuthentication:
    def test_anonymous_users_are_sent_to_login(self, client):
        response = client.get("/")
        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/"

    def test_anonymous_api_calls_get_401_not_a_redirect(self, client):
        response = client.get("/api/status")
        assert response.status_code == 401
        assert response.json()["detail"] == "authentication required"

    def test_valid_credentials_start_a_session(self, client):
        response = client.post("/login", data={"username": "admin", "password": PASSWORD})
        assert response.status_code == 303
        assert deps.SESSION_COOKIE in response.cookies

    def test_wrong_password_is_rejected(self, client):
        response = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert response.status_code == 401
        assert deps.SESSION_COOKIE not in response.cookies

    def test_unknown_user_is_rejected(self, client):
        response = client.post("/login", data={"username": "nobody", "password": PASSWORD})
        assert response.status_code == 401

    def test_session_cookie_is_httponly_and_samesite(self, client):
        response = client.post("/login", data={"username": "admin", "password": PASSWORD})
        header = response.headers["set-cookie"]
        assert "HttpOnly" in header
        assert "samesite=strict" in header.lower()

    def test_a_forged_session_cookie_is_refused(self, client):
        client.cookies.set(deps.SESSION_COOKIE, "not.a.valid.token")
        response = client.get("/")
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_login_redirect_cannot_bounce_off_site(self, client):
        response = client.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "next": "https://evil.example"},
        )
        assert response.headers["location"] == "/"

    def test_protocol_relative_redirect_is_refused(self, client):
        response = client.post(
            "/login", data={"username": "admin", "password": PASSWORD, "next": "//evil.example"}
        )
        assert response.headers["location"] == "/"

    def test_repeated_failures_are_throttled(self, client):
        from edgekit.web.routers.auth import throttle

        throttle._buckets.clear()
        for _ in range(5):
            client.post("/login", data={"username": "admin", "password": "wrong"})

        response = client.post("/login", data={"username": "admin", "password": PASSWORD})
        assert response.status_code == 429, "correct password must not bypass the lockout"
        throttle._buckets.clear()


class TestCSRF:
    def test_state_changing_post_without_a_token_is_refused(self, auth_client):
        response = auth_client.post("/peers", data={"name": "pi", "keepalive": 25})
        assert response.status_code == 403

    def test_a_token_from_another_session_is_refused(self, auth_client):
        response = auth_client.post(
            "/peers", data={"name": "pi", "keepalive": 25, "csrf_token": "a" * 64}
        )
        assert response.status_code == 403

    def test_the_matching_token_is_accepted(self, auth_client):
        token = _csrf_for(auth_client)
        response = auth_client.post(
            "/peers", data={"name": "pi", "keepalive": 25, "csrf_token": token}
        )
        assert response.status_code == 303
        assert "/peers/" in response.headers["location"]

    def test_the_token_also_works_as_a_header(self, auth_client):
        token = _csrf_for(auth_client)
        response = auth_client.post(
            "/peers", data={"name": "pi2", "keepalive": 25}, headers={"X-CSRF-Token": token}
        )
        assert response.status_code == 303


class TestPages:
    def test_dashboard_renders(self, auth_client):
        response = auth_client.get("/")
        assert response.status_code == 200
        assert "Overview" in response.text

    @pytest.mark.parametrize("path", ["/peers", "/hosts", "/diagnostics", "/settings", "/audit"])
    def test_pages_render(self, auth_client, path):
        assert auth_client.get(path).status_code == 200

    def test_security_headers_are_present(self, auth_client):
        headers = auth_client.get("/").headers
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    def test_interactive_docs_are_not_exposed(self, client):
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404

    def test_healthz_is_public_and_says_nothing_sensitive(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert set(response.json()) == {"status", "version"}


class TestApi:
    def test_status_reports_the_tunnel(self, auth_client, config):
        body = auth_client.get("/api/status").json()
        assert body["server"]["public_ip"] == config.server.public_ip
        assert body["wireguard"]["address"] == "10.50.0.1/24"
        assert body["wireguard"]["peers_total"] == 0

    def test_peers_endpoint_reflects_created_peers(self, auth_client):
        token = _csrf_for(auth_client)
        auth_client.post("/peers", data={"name": "pi", "keepalive": 25, "csrf_token": token})

        peers = auth_client.get("/api/peers").json()["peers"]
        assert len(peers) == 1
        assert peers[0]["name"] == "pi"
        assert peers[0]["address"] == "10.50.0.2"

    def test_private_keys_are_never_returned_by_the_api(self, auth_client):
        token = _csrf_for(auth_client)
        auth_client.post("/peers", data={"name": "pi", "keepalive": 25, "csrf_token": token})

        body = auth_client.get("/api/peers").text
        assert "private" not in body.lower()

    def test_health_api_returns_the_check_report(self, auth_client, monkeypatch):
        from edgekit.services.health import Check, HealthReport, Level

        async def fake_run_all(config, peers=None):
            return HealthReport([Check("ip_forward", "IP forwarding enabled", Level.OK)])

        monkeypatch.setattr("edgekit.web.routers.api.health.run_all", fake_run_all)
        body = auth_client.get("/api/health").json()
        assert body["ok"] is True
        assert body["failures"] == 0
        assert body["checks"][0]["key"] == "ip_forward"
        assert body["checks"][0]["level"] == "ok"


class TestDiagnosticsPage:
    def test_the_page_renders_without_running_health_checks(self, auth_client, monkeypatch):
        """The tab must paint immediately; probes run afterwards via /api/health."""

        async def boom(*_a, **_k):
            raise AssertionError("health.run_all must not block the diagnostics HTML")

        monkeypatch.setattr("edgekit.services.health.run_all", boom)

        response = auth_client.get("/diagnostics")
        assert response.status_code == 200
        assert "Running checks" in response.text
        assert 'data-diagnostics-src="/api/health"' in response.text
        assert "Every required check passed" not in response.text


class TestUpdateAndRemoval:
    @pytest.fixture
    def launched(self, monkeypatch):
        calls: list[tuple[str, list[str]]] = []
        monkeypatch.setattr("edgekit.jobs.launch", lambda job, args: calls.append((job, args)))
        return calls

    def _state(self, monkeypatch, **fields):
        state = jobs.JobState(**{"running": False, "exit_code": None, "output": "", **fields})
        monkeypatch.setattr("edgekit.jobs.state", lambda job, lines=400: state)

    def test_the_update_page_shows_the_running_version(self, auth_client, monkeypatch):
        self._state(monkeypatch)

        response = auth_client.get("/settings/update")

        assert response.status_code == 200
        assert __version__ in response.text
        assert "Idle" in response.text
        assert 'http-equiv="refresh"' not in response.text

    def test_a_running_update_follows_its_log(self, auth_client, monkeypatch):
        self._state(monkeypatch, running=True, output="Fetching https://github.com/…")

        response = auth_client.get("/settings/update")

        assert 'http-equiv="refresh"' in response.text
        assert "Fetching https://github.com/…" in response.text

    def test_a_failed_update_says_so(self, auth_client, monkeypatch):
        self._state(monkeypatch, exit_code=1, output="pip could not install")

        response = auth_client.get("/settings/update")

        assert "Failed" in response.text
        assert "exit 1" in response.text

    def test_starting_an_update_launches_the_job(self, auth_client, launched):
        response = auth_client.post(
            "/settings/update", data={"csrf_token": _csrf_for(auth_client)}
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/settings/update"
        assert launched == [("update", ["update"])]

    def test_an_update_without_a_csrf_token_is_refused(self, auth_client, launched):
        response = auth_client.post("/settings/update", data={})

        assert response.status_code == 403
        assert launched == []

    def test_a_launch_failure_reaches_the_operator(self, auth_client, monkeypatch):
        def unavailable(job, args):
            raise jobs.JobError("systemd-run is not available")

        monkeypatch.setattr("edgekit.jobs.launch", unavailable)

        response = auth_client.post(
            "/settings/update", data={"csrf_token": _csrf_for(auth_client)}
        )

        assert "systemd-run" in response.headers["location"]

    def test_the_settings_page_offers_update_and_removal(self, auth_client):
        response = auth_client.get("/settings")

        assert 'href="/settings/update"' in response.text
        assert 'action="/settings/uninstall"' in response.text

    def test_removal_requires_typing_remove(self, auth_client, launched):
        response = auth_client.post(
            "/settings/uninstall",
            data={"csrf_token": _csrf_for(auth_client), "confirm": "yes"},
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]
        assert launched == []

    def test_confirmed_removal_starts_outside_the_panel(self, auth_client, launched):
        response = auth_client.post(
            "/settings/uninstall",
            data={"csrf_token": _csrf_for(auth_client), "confirm": "Remove", "keep_dns": "true"},
        )

        assert response.status_code == 200
        assert "being removed" in response.text
        assert launched == [("uninstall", ["uninstall", "--yes", "--keep-dns"])]


def _csrf_for(client: TestClient) -> str:
    """Recompute the CSRF token the same way the templates do."""
    import hashlib
    import hmac

    cookie = client.cookies.get(deps.SESSION_COOKIE, "")
    secret = deps.get_config().panel.session_secret.encode()
    return hmac.new(secret, cookie.encode(), hashlib.sha256).hexdigest()
