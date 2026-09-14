"""Origin certificate handling: parsing, key matching, and coverage."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from edgekit.services.certificates import (
    CertificateError,
    inspect_certificate,
    validate_key_matches,
)


def make_cert(
    hostnames: list[str],
    *,
    days: int = 365,
    key: rsa.RSAPrivateKey | None = None,
) -> tuple[str, str]:
    """Build a self-signed certificate covering ``hostnames``. Returns (cert_pem, key_pem)."""
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    )


@pytest.fixture(scope="module")
def wildcard_pair():
    return make_cert(["*.example.com", "example.com"])


class TestInspect:
    def test_reads_the_hostnames_and_dates(self, wildcard_pair):
        info = inspect_certificate(wildcard_pair[0])

        assert info.hostnames == ["*.example.com", "example.com"]
        assert info.expired is False
        assert 360 <= info.days_remaining <= 366

    def test_an_expired_certificate_is_flagged(self):
        cert_pem, _ = make_cert(["example.com"], days=-1)
        assert inspect_certificate(cert_pem).expired is True

    def test_garbage_gets_a_readable_error(self):
        with pytest.raises(CertificateError, match="BEGIN CERTIFICATE"):
            inspect_certificate("this is not a certificate")

    def test_a_private_key_pasted_as_a_certificate_is_rejected(self):
        """The two Cloudflare boxes are adjacent and easy to mix up."""
        _, key_pem = make_cert(["example.com"])
        with pytest.raises(CertificateError):
            inspect_certificate(key_pem)


class TestCoverage:
    def test_a_wildcard_covers_subdomains(self, wildcard_pair):
        info = inspect_certificate(wildcard_pair[0])

        assert info.covers("retro.example.com")
        assert info.covers("api.example.com")
        assert info.covers("example.com")

    def test_a_wildcard_does_not_cover_deeper_labels(self, wildcard_pair):
        """*.example.com matches one label only — a.b.example.com is not covered."""
        assert inspect_certificate(wildcard_pair[0]).covers("a.b.example.com") is False

    def test_other_domains_are_not_covered(self, wildcard_pair):
        info = inspect_certificate(wildcard_pair[0])

        assert info.covers("example.org") is False
        assert info.covers("notexample.com") is False

    def test_matching_is_case_insensitive(self, wildcard_pair):
        assert inspect_certificate(wildcard_pair[0]).covers("Retro.Example.COM")


class TestKeyMatching:
    def test_a_matching_pair_is_accepted(self, wildcard_pair):
        validate_key_matches(*wildcard_pair)

    def test_a_mismatched_key_is_rejected(self):
        cert_pem, _ = make_cert(["example.com"])
        _, other_key = make_cert(["example.com"])

        with pytest.raises(CertificateError, match="does not match"):
            validate_key_matches(cert_pem, other_key)

    def test_a_certificate_pasted_as_the_key_is_rejected(self, wildcard_pair):
        with pytest.raises(CertificateError, match="PEM private key"):
            validate_key_matches(wildcard_pair[0], wildcard_pair[0])

    def test_garbage_key_is_rejected(self, wildcard_pair):
        with pytest.raises(CertificateError, match="PEM private key"):
            validate_key_matches(wildcard_pair[0], "nope")


class TestConfigStorage:
    def test_the_key_is_encrypted_at_rest_but_the_certificate_is_not(
        self, tmp_path, config, wildcard_pair
    ):
        cert_pem, key_pem = wildcard_pair
        config.tls.certificate = cert_pem
        config.tls.certificate_key = key_pem
        config.tls.name = "Cloudflare Origin - example.com"

        path = tmp_path / "config.yaml"
        config.save(path)
        raw = path.read_text()

        assert "PRIVATE KEY" not in raw, "the private key must not be stored in plaintext"
        assert "enc:" in raw

        from edgekit.config import Config

        loaded = Config.load(path)
        assert loaded.tls.certificate_key == key_pem
        assert loaded.tls.certificate == cert_pem
        assert loaded.tls.present is True


class FakeNPMClient:
    """Stands in for NPMClient: records uploads and pretends to hold the results."""

    def __init__(self, *args, existing_ids: list[int] | None = None, **kwargs) -> None:
        self.uploads: list[tuple[str, str]] = []
        self.stored: list[int] = list(existing_ids or [])
        self.next_id = 10
        self.repointed: list[tuple[int, int]] = []
        self.letsencrypt: list[dict] = []
        self.requested: list[dict] = []
        #: How long a Let's Encrypt request takes, and what it fails with, if anything.
        self.issuance_delay = 0.0
        self.issuance_error: Exception | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def certificate_exists(self, cert_id: int) -> bool:
        return int(cert_id) in self.stored

    async def upload_custom_certificate(self, nice_name, certificate_pem, key_pem) -> int:
        self.next_id += 1
        self.uploads.append((nice_name, certificate_pem))
        self.stored.append(self.next_id)
        return self.next_id

    async def repoint_hosts(self, old_id: int, new_id: int) -> None:
        self.repointed.append((old_id, new_id))

    async def find_letsencrypt_certificate(self, domains):
        matches = [c for c in self.letsencrypt if set(c["domain_names"]) == set(domains)]
        return matches[-1] if matches else None

    async def create_letsencrypt_certificate(self, nice_name, domains, **kwargs) -> dict:
        if self.issuance_delay:
            await asyncio.sleep(self.issuance_delay)
        if self.issuance_error:
            raise self.issuance_error
        self.next_id += 1
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90)
        record = {
            "id": self.next_id,
            "nice_name": nice_name,
            "domain_names": domains,
            "expires_on": expires.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.requested.append({**record, **kwargs})
        self.letsencrypt.append(record)
        self.stored.append(self.next_id)
        return record


@pytest.fixture
def npm(monkeypatch):
    """One client instance for the whole test, whichever way the service constructs it."""
    client = FakeNPMClient()
    monkeypatch.setattr(
        "edgekit.services.certificates.NPMClient", lambda *a, **k: client
    )
    return client


class TestIdempotentInstall:
    """NPM cannot update a certificate in place, so every install churns every proxy host."""

    async def _install(self, session, config, pair, **kwargs):
        from edgekit.services.certificates import install_manual_certificate

        return await install_manual_certificate(session, config, pair[0], pair[1], **kwargs)

    async def test_the_first_install_uploads(self, db_session, config, npm, wildcard_pair):
        outcome = await self._install(db_session, config, wildcard_pair)

        assert outcome["status"] == "installed"
        assert len(npm.uploads) == 1

    async def test_installing_the_same_certificate_again_changes_nothing(
        self, db_session, config, npm, wildcard_pair
    ):
        first = await self._install(db_session, config, wildcard_pair)
        second = await self._install(db_session, config, wildcard_pair)

        assert second["status"] == "unchanged"
        assert second["certificate_id"] == first["certificate_id"]
        assert len(npm.uploads) == 1, "a re-provision must not re-upload an unchanged cert"

    async def test_whitespace_differences_do_not_count_as_a_new_certificate(
        self, db_session, config, npm, wildcard_pair
    ):
        await self._install(db_session, config, wildcard_pair)
        padded = ("\n" + wildcard_pair[0].strip() + "\n\n", wildcard_pair[1])

        assert (await self._install(db_session, config, padded))["status"] == "unchanged"
        assert len(npm.uploads) == 1

    async def test_a_different_certificate_is_installed(
        self, db_session, config, npm, wildcard_pair
    ):
        await self._install(db_session, config, wildcard_pair)
        replacement = make_cert(["*.example.com", "example.com"])

        assert (await self._install(db_session, config, replacement))["status"] == "installed"
        assert len(npm.uploads) == 2

    async def test_a_wiped_npm_gets_the_certificate_back(
        self, db_session, config, npm, wildcard_pair
    ):
        """`edgekit npm reset` destroys NPM's data without telling edgekit."""
        await self._install(db_session, config, wildcard_pair)
        npm.stored.clear()

        assert (await self._install(db_session, config, wildcard_pair))["status"] == "installed"
        assert len(npm.uploads) == 2

    async def test_force_uploads_regardless(self, db_session, config, npm, wildcard_pair):
        await self._install(db_session, config, wildcard_pair)

        outcome = await self._install(db_session, config, wildcard_pair, force=True)

        assert outcome["status"] == "installed"
        assert len(npm.uploads) == 2


def _npm_time(days: int) -> str:
    when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
    return when.strftime("%Y-%m-%d %H:%M:%S")


class TestLetsEncrypt:
    """Direct mode: browsers connect to the origin, so its certificate must be publicly trusted."""

    @pytest.fixture(autouse=True)
    def real_mailbox(self, config):
        config.npm.admin_email = "ops@blockey.ir"

    async def test_a_wildcard_is_issued_through_the_cloudflare_dns_challenge(
        self, db_session, config, npm
    ):
        from edgekit.services.certificates import install_letsencrypt

        outcome = await install_letsencrypt(db_session, config)

        assert outcome["status"] == "issued"
        request = npm.requested[0]
        assert request["domain_names"] == ["*.example.com", "example.com"]
        assert request["dns_provider"] == "cloudflare"
        assert request["dns_credentials"] == "dns_cloudflare_api_token=cf-token"
        assert request["email"] == "ops@blockey.ir"

    async def test_a_certificate_npm_already_holds_is_reused(self, db_session, config, npm):
        from edgekit.services.certificates import install_letsencrypt

        npm.letsencrypt.append(
            {"id": 5, "domain_names": ["example.com", "*.example.com"], "expires_on": _npm_time(80)}
        )

        outcome = await install_letsencrypt(db_session, config)

        assert outcome == {**outcome, "status": "unchanged", "certificate_id": "5"}
        assert npm.requested == []

    async def test_one_npm_failed_to_renew_is_replaced(self, db_session, config, npm):
        from edgekit.services.certificates import install_letsencrypt

        npm.letsencrypt.append(
            {"id": 5, "domain_names": ["*.example.com", "example.com"], "expires_on": _npm_time(5)}
        )

        assert (await install_letsencrypt(db_session, config))["status"] == "issued"

    async def test_hosts_move_off_the_origin_certificate(
        self, db_session, config, npm, wildcard_pair
    ):
        """NPM hosts edgekit did not create are still on the old certificate after a switch."""
        from edgekit.services.certificates import install_letsencrypt, install_manual_certificate

        origin = await install_manual_certificate(db_session, config, *wildcard_pair)
        issued = await install_letsencrypt(db_session, config)

        assert npm.repointed == [
            (int(origin["certificate_id"]), int(issued["certificate_id"]))
        ]

    async def test_switching_back_reinstalls_the_origin_certificate(
        self, db_session, config, npm, wildcard_pair
    ):
        """The origin certificate's fingerprint must not make it look installed after a switch."""
        from edgekit.services.certificates import install_letsencrypt, install_manual_certificate

        await install_manual_certificate(db_session, config, *wildcard_pair)
        await install_letsencrypt(db_session, config)

        back = await install_manual_certificate(db_session, config, *wildcard_pair)

        assert back["status"] == "installed"
        assert len(npm.uploads) == 2

    async def test_a_slow_issuance_reports_progress_instead_of_looking_hung(
        self, db_session, config, npm, monkeypatch, caplog
    ):
        from edgekit.services import certificates

        monkeypatch.setattr(certificates, "LETSENCRYPT_PROGRESS_INTERVAL", 0.01)
        monkeypatch.setattr(
            certificates.dockerx,
            "logs",
            lambda container, lines=100: (
                "\x1b[1;34m[SSL]\x1b[0m › ℹ info Installing cloudflare...\n"
            ),
        )
        npm.issuance_delay = 0.05

        with caplog.at_level(logging.INFO, logger="edgekit.certificates"):
            outcome = await certificates.install_letsencrypt(db_session, config)

        assert outcome["status"] == "issued"
        progress = [r.getMessage() for r in caplog.records if "still obtaining" in r.getMessage()]
        assert progress, "minutes of silence read as a hang"
        assert "[SSL] › ℹ info Installing cloudflare..." in progress[-1]

    async def test_a_timeout_says_npm_may_still_finish(self, db_session, config, npm):
        from edgekit.services.certificates import install_letsencrypt

        npm.issuance_error = httpx.ReadTimeout("timed out")

        with pytest.raises(CertificateError, match="run `edgekit provision` again"):
            await install_letsencrypt(db_session, config)

    async def test_a_placeholder_npm_email_is_refused_before_asking_npm(
        self, db_session, config, npm
    ):
        from edgekit.services.certificates import install_letsencrypt

        config.npm.admin_email = "admin@example.com"

        with pytest.raises(CertificateError, match="npm password --email"):
            await install_letsencrypt(db_session, config)
        assert npm.requested == []


@pytest.mark.parametrize(
    "email,placeholder",
    [
        ("admin@example.com", True),
        ("root@localhost", True),
        ("me@server.local", True),
        ("ops@blockey.ir", False),
        ("someone@gmail.com", False),
    ],
)
def test_placeholder_emails_are_recognised(email, placeholder):
    from edgekit.services.certificates import is_placeholder_email

    assert is_placeholder_email(email) is placeholder


@pytest.mark.parametrize(
    "raw",
    ["2026-12-13 10:00:00", "2026-12-13T10:00:00Z", "2026-12-13T10:00:00+00:00"],
)
def test_npm_timestamps_parse_as_utc(raw):
    from edgekit.services.certificates import parse_npm_timestamp

    assert parse_npm_timestamp(raw) == dt.datetime(2026, 12, 13, 10, tzinfo=dt.timezone.utc)


def test_the_latest_certificate_line_is_picked_out_of_npm_logs(monkeypatch):
    from edgekit.services import certificates

    monkeypatch.setattr(
        certificates.dockerx,
        "logs",
        lambda container, lines=100: (
            "[Nginx] › ℹ info Reloading Nginx\n"
            "\x1b[32m[SSL]\x1b[0m › ℹ info Requesting LetsEncrypt certificates via Cloudflare\n"
            "[Global] › ℹ info Backend PID 190 listening\n"
        ),
    )

    assert certificates.latest_npm_ssl_line("npm") == (
        "[SSL] › ℹ info Requesting LetsEncrypt certificates via Cloudflare"
    )


def test_an_unparseable_npm_timestamp_is_none():
    from edgekit.services.certificates import parse_npm_timestamp

    assert parse_npm_timestamp("soon") is None
    assert parse_npm_timestamp(None) is None


class TestValidatePair:
    def test_an_expired_certificate_is_refused(self):
        from edgekit.services.certificates import validate_pair

        pair = make_cert(["example.com"], days=-1)
        with pytest.raises(CertificateError, match="expired"):
            validate_pair(*pair)

    def test_a_valid_pair_returns_its_details(self, wildcard_pair):
        from edgekit.services.certificates import validate_pair

        assert validate_pair(*wildcard_pair).hostnames == ["*.example.com", "example.com"]


class TestCoverageWarnings:
    def _info(self, hostnames):
        return inspect_certificate(make_cert(hostnames)[0])

    def test_a_wildcard_covering_the_zone_warns_about_nothing(self):
        from edgekit.services.certificates import coverage_warnings

        info = self._info(["*.example.com", "example.com"])
        assert coverage_warnings(info, "example.com", ["a.example.com"]) == []

    def test_hosts_outside_the_certificate_are_named(self):
        from edgekit.services.certificates import coverage_warnings

        info = self._info(["a.example.com"])
        warnings = coverage_warnings(info, "example.com", ["a.example.com", "b.example.com"])

        assert any("b.example.com" in w for w in warnings)
        assert not any("a.example.com" in w.split(":")[-1] for w in warnings if "not covered" in w)

    def test_a_single_host_certificate_warns_about_future_subdomains(self):
        from edgekit.services.certificates import coverage_warnings

        info = self._info(["a.example.com"])
        assert any("*.example.com" in w for w in coverage_warnings(info, "example.com", []))
