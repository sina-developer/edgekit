"""Certificate and TLS-layer health checks — the ones that explain a Cloudflare 525."""

from __future__ import annotations

import datetime as dt

import pytest
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


class _NoopNPM:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def find_proxy_host(self, domain):
        return None

    async def upsert_proxy_host(self, spec):
        return {"id": 1}
