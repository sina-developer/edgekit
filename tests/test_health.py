"""Certificate and TLS-layer health checks — the ones that explain a Cloudflare 525."""

from __future__ import annotations

import datetime as dt

import httpx
import pytest
import respx
from test_certificates import make_cert

from edgekit.services import health
from edgekit.services.health import Level
from edgekit.services.hosts import (
    SETTING_CERT_ID,
    HostService,
    set_setting,
)


def _by_key(checks, key):
    return next(c for c in checks if c.key == key)


class TestExpiryWarnings:
    """Cloudflare sends no expiry notice for Origin CA certificates. This is the only one."""

    def _days(self, days: int):
        when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
        return health._expiry_checks(when.isoformat())

    def test_a_distant_expiry_is_fine(self):
        assert self._days(400)[0].level is Level.OK

    def test_a_month_out_warns(self):
        assert self._days(20)[0].level is Level.WARN

    def test_a_week_out_fails(self):
        assert self._days(3)[0].level is Level.FAIL

    def test_an_expired_certificate_fails_and_says_how_long_ago(self):
        check = self._days(-5)[0]
        assert check.level is Level.FAIL
        assert "expired" in check.detail

    def test_an_unparseable_expiry_produces_no_check_rather_than_a_wrong_one(self):
        assert health._expiry_checks("not a date") == []
        assert health._expiry_checks("") == []


class TestNginxConfigCheck:
    async def test_a_rejected_configuration_is_a_failure_naming_525(self, config, monkeypatch):
        monkeypatch.setattr(
            health.dockerx,
            "nginx_config_test",
            lambda container, timeout=30: (False, "nginx: [emerg] cannot load certificate"),
        )
        check = await health._check_nginx_config(config)

        assert check.level is Level.FAIL
        assert "525" in check.remedy

    async def test_it_passes_when_nginx_is_happy(self, config, monkeypatch):
        monkeypatch.setattr(
            health.dockerx, "nginx_config_test", lambda container, timeout=30: (True, "ok")
        )
        assert (await health._check_nginx_config(config)).level is Level.OK

    async def test_an_unrunnable_test_is_skipped_not_failed(self, config, monkeypatch):
        monkeypatch.setattr(
            health.dockerx,
            "nginx_config_test",
            lambda container, timeout=30: (None, "container is not running"),
        )
        assert (await health._check_nginx_config(config)).level is Level.SKIP


class TestCertificateChecks:
    @pytest.fixture(autouse=True)
    def no_docker(self, monkeypatch):
        monkeypatch.setattr(
            health.dockerx, "nginx_config_test", lambda container, timeout=30: (None, "")
        )

    async def test_a_missing_certificate_fails_and_explains_the_525(self, config, clean_db):
        checks = await health._check_certificate(config)

        check = _by_key(checks, "origin_cert")
        assert check.level is Level.FAIL
        assert "525" in check.remedy

    async def test_an_installed_certificate_passes(self, config, db_session):
        set_setting(db_session, SETTING_CERT_ID, "7")
        db_session.commit()

        checks = await health._check_certificate(config)

        assert _by_key(checks, "origin_cert").level is Level.OK

    async def test_a_host_outside_the_certificate_is_reported(
        self, config, db_session, fake_wg, monkeypatch
    ):
        config.tls.certificate = make_cert(["a.example.com"])[0]
        set_setting(db_session, SETTING_CERT_ID, "7")
        service = HostService(db_session, config)
        monkeypatch.setattr(service, "_cloudflare_client", lambda: None)
        monkeypatch.setattr(service, "_npm_client", lambda: _NoopNPM())
        await service.create(domain="b.example.com", forward_port=80, forward_host="10.50.0.2")
        db_session.commit()

        checks = await health._check_certificate(config)

        coverage = _by_key(checks, "cert_coverage")
        assert coverage.level is Level.FAIL
        assert "b.example.com" in coverage.detail

    async def test_a_wildcard_covers_every_host(
        self, config, db_session, fake_wg, monkeypatch
    ):
        config.tls.certificate = make_cert(["*.example.com", "example.com"])[0]
        set_setting(db_session, SETTING_CERT_ID, "7")
        service = HostService(db_session, config)
        monkeypatch.setattr(service, "_cloudflare_client", lambda: None)
        monkeypatch.setattr(service, "_npm_client", lambda: _NoopNPM())
        await service.create(domain="b.example.com", forward_port=80, forward_host="10.50.0.2")
        db_session.commit()

        checks = await health._check_certificate(config)

        assert _by_key(checks, "cert_coverage").level is Level.OK


ORIGIN_ISSUER = (
    "ST=California,L=San Francisco,OU=CloudFlare Origin SSL Certificate Authority,"
    "O=CloudFlare\\, Inc.,C=US"
)


class TestPublicAssessment:
    """What a browser is shown, judged against the mode. The first case is the reported bug."""

    def _probe(self, **fields):
        return health.PublicProbe("edgekit.example.com", **fields)

    def test_a_dns_only_record_in_front_of_an_origin_certificate_fails(self, config):
        probe = self._probe(
            addresses=["203.0.113.10"], trusted=False, issuer=ORIGIN_ISSUER,
            error="unable to get local issuer certificate",
        )

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.FAIL
        assert "only Cloudflare's proxy trusts" in check.detail
        assert "Proxied" in check.remedy
        assert "edgekit ssl mode direct" in check.remedy
        assert retry, "a proxy toggle applied moments ago explains this, so it is worth waiting"

    def test_without_a_token_the_advice_does_not_promise_edgekit_can_fix_dns(self, config):
        config.cloudflare.api_token = ""
        config.cloudflare.enabled = False
        probe = self._probe(addresses=["203.0.113.10"], trusted=False, issuer=ORIGIN_ISSUER)

        check, _ = health.assess_public(probe, config)

        assert "edgekit cloudflare token --zone example.com" in check.remedy
        assert "stored token" not in check.remedy

    def test_with_a_token_the_advice_is_to_provision(self, config):
        probe = self._probe(addresses=["203.0.113.10"], trusted=False, issuer=ORIGIN_ISSUER)

        check, _ = health.assess_public(probe, config)

        assert "stored token" in check.remedy

    def test_the_origin_certificate_in_direct_mode_is_not_a_dns_wait(self, config):
        config.tls.mode = "direct"
        probe = self._probe(addresses=["203.0.113.10"], trusted=False, issuer=ORIGIN_ISSUER)

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.FAIL
        assert "edgekit provision" in check.remedy
        assert not retry

    def test_proxied_and_trusted_passes(self, config):
        probe = self._probe(
            addresses=["104.21.8.1"], trusted=True, issuer="C=US,O=Google Trust Services,CN=WE1",
            status=200,
        )

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.OK
        assert "Google Trust Services" in check.detail
        assert not retry

    def test_direct_mode_on_the_origin_passes(self, config):
        config.tls.mode = "direct"
        probe = self._probe(
            addresses=["203.0.113.10"], trusted=True, issuer="C=US,O=Let's Encrypt,CN=R11",
            status=303,
        )

        assert health.assess_public(probe, config)[0].level is Level.OK

    def test_direct_mode_still_behind_cloudflare_waits_for_dns(self, config):
        config.tls.mode = "direct"
        probe = self._probe(addresses=["104.21.8.1"], trusted=True, status=200)

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.WARN
        assert retry

    def test_a_525_names_direct_mode_as_the_way_out(self, config):
        probe = self._probe(addresses=["104.21.8.1"], trusted=True, status=525)

        check, _ = health.assess_public(probe, config)

        assert check.level is Level.FAIL
        assert "edgekit ssl mode direct" in check.remedy

    def test_a_slow_upstream_is_not_reported_as_a_tls_problem(self, config):
        probe = self._probe(addresses=["104.21.8.1"], trusted=True, status=None)

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.WARN
        assert "TLS is fine" in check.remedy
        assert not retry

    def test_a_server_that_cannot_look_the_name_up_is_not_a_missing_record(self, config):
        """The reported run: public DNS unreachable, the local resolver blind to the name."""
        probe = self._probe(
            resolved_by="server",
            error="does not resolve on this server: [Errno -2] Name or service not known",
        )

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.WARN
        assert "curl -sI https://edgekit.example.com" in check.remedy
        assert "No A record" not in check.remedy
        assert not retry, "waiting cannot make this server see public DNS"

    def test_a_name_that_does_not_resolve_fails(self, config):
        check, retry = health.assess_public(self._probe(error="does not resolve"), config)

        assert check.level is Level.FAIL
        assert retry

    def test_an_unreachable_name_is_a_warning_not_a_verdict(self, config):
        probe = self._probe(addresses=["203.0.113.10"], error="timed out")

        check, retry = health.assess_public(probe, config)

        assert check.level is Level.WARN
        assert not retry

    def test_the_issuer_is_named_the_way_people_recognise_it(self):
        assert health._issuer_name(ORIGIN_ISSUER) == "CloudFlare, Inc."


RESOLVER_URLS = [url for url, _ in health.PUBLIC_RESOLVERS]


class TestPublicResolution:
    """A server's resolver caches "no such name" for 30 minutes, and on some networks cannot
    see proxied names at all. Browsers do not use it."""

    def test_resolvers_are_also_reached_by_ip_address(self):
        """Networks that filter the resolvers' hostnames often still pass their addresses."""
        assert RESOLVER_URLS[0].startswith("https://1.1.1.1/")
        assert any(url.startswith("https://8.8.8.8/") for url in RESOLVER_URLS)

    @respx.mock
    def test_public_dns_answers_with_its_addresses(self):
        route = respx.get(RESOLVER_URLS[0]).mock(
            return_value=httpx.Response(200, json={"Status": 0, "Answer": [
                {"type": 5, "data": "edge.example."},
                {"type": 1, "data": "188.114.97.3"},
                {"type": 1, "data": "188.114.96.3"},
            ]})
        )

        assert health.resolve_public("edgekit.blockey.ir") == (
            ["188.114.96.3", "188.114.97.3"], ""
        )
        assert route.calls[0].request.url.params["name"] == "edgekit.blockey.ir"

    @respx.mock
    def test_a_name_public_dns_does_not_know_is_reported_as_such(self):
        respx.get(RESOLVER_URLS[0]).mock(return_value=httpx.Response(200, json={"Status": 3}))

        assert health.resolve_public("gone.blockey.ir") == ([], "does not exist in public DNS")

    @respx.mock
    def test_blocked_resolvers_fall_through_to_the_next(self):
        for url in RESOLVER_URLS[:-1]:
            respx.get(url).mock(side_effect=httpx.ConnectError("blocked"))
        respx.get(RESOLVER_URLS[-1]).mock(
            return_value=httpx.Response(200, json={"Status": 0, "Answer": [
                {"type": 1, "data": "195.177.255.61"},
            ]})
        )

        assert health.resolve_public("yekja.blockey.ir") == (["195.177.255.61"], "")

    @respx.mock
    def test_no_reachable_public_resolver_leaves_it_to_the_server(self):
        for url in RESOLVER_URLS:
            respx.get(url).mock(side_effect=httpx.ConnectError("blocked"))

        assert health.resolve_public("edgekit.blockey.ir") == (None, "")

    def test_the_servers_resolver_is_not_asked_when_public_dns_answered(self, monkeypatch):
        def must_not_run(domain, port):
            raise AssertionError("the local resolver's cached answer must not decide this")

        monkeypatch.setattr(health, "_resolve_locally", must_not_run)

        probe = health.probe_public_https(
            "gone.example.com", resolve=lambda domain: ([], "does not exist in public DNS")
        )

        assert probe.addresses == []
        assert probe.error == "does not exist in public DNS"


class TestLocalTlsProbe:
    async def test_a_handshake_without_a_response_is_an_upstream_warning(self, monkeypatch):
        """An offline peer made doctor report TLS failures that were nothing of the sort."""
        monkeypatch.setattr(health, "_https_sni", lambda address, domain, port: None)

        check = await health._probe_local_proxy("yekja.example.com", 443)

        assert check.level is Level.WARN
        assert "Not a certificate problem" in check.remedy


@pytest.fixture
def tls_server(tmp_path):
    """A local TLS server presenting a certificate from an issuer of the test's choosing."""
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    servers = []

    def start(organizational_unit: str) -> int:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256())
        )
        cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        listener.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                conn.settimeout(2)
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1024)
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        servers.append((stop, listener, thread))
        return listener.getsockname()[1]

    yield start
    for stop, listener, thread in servers:
        stop.set()
        thread.join(2)
        listener.close()


def test_an_origin_certificate_is_recognised_on_the_wire(tls_server):
    port = tls_server("CloudFlare Origin SSL Certificate Authority")

    probe = health.probe_public_https(
        "localhost", port=port, timeout=3, resolve=lambda domain: (["127.0.0.1"], "")
    )

    assert probe.trusted is False
    assert probe.origin_certificate
    assert "127.0.0.1" in probe.addresses


class _NoopNPM:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def find_proxy_host(self, domain):
        return None

    async def upsert_proxy_host(self, spec):
        return {"id": 1}
