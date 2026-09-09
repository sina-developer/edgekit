"""Proxy host orchestration across the local database, NPM, and Cloudflare."""

from __future__ import annotations

import pytest

from edgekit.services.hosts import HostError, HostService, set_setting, validate_domain
from edgekit.services.peers import PeerService


class FakeNPM:
    """Stands in for NPMClient, recording what the service asked it to do."""

    def __init__(self) -> None:
        self.upserted: list = []
        self.deleted: list[int] = []
        self.restored: list[tuple[int, dict]] = []
        self.existing: dict | None = None
        self.next_id = 100

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def find_proxy_host(self, domain: str):
        return self.existing

    async def upsert_proxy_host(self, spec):
        self.upserted.append(spec)
        self.next_id += 1
        return {"id": self.next_id}

    async def restore_proxy_host(self, host_id: int, snapshot: dict):
        self.restored.append((host_id, snapshot))
        return snapshot

    async def delete_proxy_host(self, host_id: int):
        self.deleted.append(host_id)


class FakeCloudflare:
    def __init__(self, *, fail: bool = False) -> None:
        self.records: list[tuple[str, str]] = []
        self.deleted: list[str] = []
        self.fail = fail

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def upsert_a_record(self, zone_id, name, ip, proxied=True):
        if self.fail:
            from edgekit.services.cloudflare import CloudflareError

            raise CloudflareError("zone is not editable")
        self.records.append((name, ip))
        return {"id": f"rec-{len(self.records)}"}

    async def delete_dns_record(self, zone_id, record_id):
        self.deleted.append(record_id)


@pytest.fixture(autouse=True)
def nginx_test_unavailable(monkeypatch):
    """No Docker in the suite: nginx -t cannot run, and that must never look like a failure."""
    monkeypatch.setattr(
        "edgekit.services.hosts.dockerx.nginx_config_test",
        lambda container, timeout=30: (None, "no docker in tests"),
    )


@pytest.fixture
def service(db_session, config, fake_wg, monkeypatch):
    svc = HostService(db_session, config)
    npm, cloudflare = FakeNPM(), FakeCloudflare()
    monkeypatch.setattr(svc, "_npm_client", lambda: npm)
    monkeypatch.setattr(svc, "_cloudflare_client", lambda: cloudflare)
    svc.fake_npm, svc.fake_cf = npm, cloudflare
    set_setting(db_session, "npm_certificate_id", "7")
    return svc


class TestValidation:
    @pytest.mark.parametrize(
        "raw,expected",
        [("Retro.Example.COM", "retro.example.com"), ("a.example.com.", "a.example.com")],
    )
    def test_domains_are_normalised(self, raw, expected):
        assert validate_domain(raw) == expected

    @pytest.mark.parametrize("bad", ["", "-bad.example.com", "has space.com", "a" * 300])
    def test_bad_domains_are_rejected(self, bad):
        with pytest.raises(HostError):
            validate_domain(bad)

    async def test_port_must_be_in_range(self, service):
        with pytest.raises(HostError, match="between 1 and 65535"):
            await service.create(domain="a.example.com", forward_port=70000,
                                 forward_host="10.50.0.2")

    async def test_scheme_must_be_http_or_https(self, service):
        with pytest.raises(HostError, match="http or https"):
            await service.create(domain="a.example.com", forward_port=80,
                                 forward_host="10.50.0.2", scheme="ftp")

    async def test_a_target_is_required(self, service):
        with pytest.raises(HostError, match="peer or an explicit forward host"):
            await service.create(domain="a.example.com", forward_port=80)

    async def test_duplicate_domains_are_refused(self, service):
        await service.create(domain="a.example.com", forward_port=80, forward_host="10.50.0.2")
        with pytest.raises(HostError, match="already configured"):
            await service.create(domain="a.example.com", forward_port=81,
                                 forward_host="10.50.0.3")


class TestPublishing:
    async def test_publishing_via_a_peer_uses_the_peer_address(self, service, db_session, config):
        peer = PeerService(db_session, config).create("pi")
        db_session.flush()

        host = await service.create(domain="retro.example.com", forward_port=3001,
                                    peer_id=peer.id)

        assert host.forward_host == "10.50.0.2"
        assert host.npm_host_id == 101
        assert service.fake_npm.upserted[0].certificate_id == 7
        assert service.fake_cf.records == [("retro.example.com", "203.0.113.10")]
        assert host.cloudflare_record_id == "rec-1"

    async def test_dns_can_be_skipped(self, service):
        await service.create(domain="a.example.com", forward_port=80,
                             forward_host="10.50.0.2", manage_dns=False)
        assert service.fake_cf.records == []

    async def test_a_dns_failure_does_not_block_the_proxy_host(self, service, monkeypatch):
        """The operator may manage DNS elsewhere; NPM is still worth configuring."""
        monkeypatch.setattr(service, "_cloudflare_client", lambda: FakeCloudflare(fail=True))

        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="10.50.0.2")

        assert host.npm_host_id is not None
        assert host.cloudflare_record_id is None

    async def test_unknown_peer_is_rejected(self, service):
        with pytest.raises(HostError, match="No peer with id"):
            await service.create(domain="a.example.com", forward_port=80, peer_id=999)


class TestLifecycle:
    async def test_updating_the_port_re_pushes_to_npm(self, service):
        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="10.50.0.2")
        await service.update(host.id, forward_port=8080)

        assert service.fake_npm.upserted[-1].forward_port == 8080

    async def test_repointing_to_a_peer_follows_its_address(self, service, db_session, config):
        peer = PeerService(db_session, config).create("pi", address="10.50.0.9")
        db_session.flush()
        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="192.0.2.1")

        await service.update(host.id, peer_id=peer.id)
        assert host.forward_host == "10.50.0.9"

    async def test_delete_removes_the_npm_host_and_keeps_dns_by_default(self, service):
        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="10.50.0.2")
        npm_id = host.npm_host_id

        await service.delete(host.id)

        assert service.fake_npm.deleted == [npm_id]
        assert service.fake_cf.deleted == []
        assert service.list() == []

    async def test_delete_can_also_remove_the_dns_record(self, service):
        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="10.50.0.2")
        await service.delete(host.id, remove_dns=True)
        assert service.fake_cf.deleted == ["rec-1"]

    async def test_resync_pushes_every_host(self, service):
        await service.create(domain="a.example.com", forward_port=80, forward_host="10.50.0.2")
        await service.create(domain="b.example.com", forward_port=81, forward_host="10.50.0.3")
        service.fake_npm.upserted.clear()

        outcomes = await service.resync_all()

        assert outcomes == {"a.example.com": "ok", "b.example.com": "ok"}
        assert len(service.fake_npm.upserted) == 2

    async def test_repointing_a_peer_updates_its_hosts(self, service, db_session, config):
        peer = PeerService(db_session, config).create("pi")
        db_session.flush()
        await service.create(domain="a.example.com", forward_port=80, peer_id=peer.id)

        peer.address = "10.50.0.50"
        db_session.flush()
        await service.repoint_peer_hosts(peer)

        assert service.fake_npm.upserted[-1].forward_host == "10.50.0.50"


class TestNginxValidation:
    """NPM answers 200 for configuration nginx then refuses to load — the 525 pathway."""

    @pytest.fixture
    def nginx_rejects(self, monkeypatch):
        monkeypatch.setattr(
            "edgekit.services.hosts.dockerx.nginx_config_test",
            lambda container, timeout=30: (
                False,
                'nginx: [emerg] cannot load certificate "/data/custom_ssl/npm-7/fullchain.pem"',
            ),
        )

    async def test_a_rejected_configuration_is_rolled_back_to_the_previous_host(
        self, service, nginx_rejects
    ):
        service.fake_npm.existing = {"id": 42, "domain_names": ["a.example.com"],
                                     "forward_port": 80, "certificate_id": 3}

        with pytest.raises(HostError, match="nginx rejected"):
            await service.create(domain="a.example.com", forward_port=81,
                                 forward_host="10.50.0.2")

        assert service.fake_npm.restored == [(42, service.fake_npm.existing)]

    async def test_a_rejected_new_host_is_removed_rather_than_left_broken(
        self, service, nginx_rejects
    ):
        with pytest.raises(HostError, match="nginx rejected"):
            await service.create(domain="a.example.com", forward_port=80,
                                 forward_host="10.50.0.2")

        assert service.fake_npm.deleted == [101]
        assert service.fake_npm.restored == []

    async def test_the_nginx_output_reaches_the_operator(self, service, nginx_rejects):
        with pytest.raises(HostError, match="cannot load certificate"):
            await service.create(domain="a.example.com", forward_port=80,
                                 forward_host="10.50.0.2")

    async def test_an_unavailable_nginx_test_is_not_treated_as_a_failure(self, service):
        """No Docker means we could not check — never a reason to undo good configuration."""
        host = await service.create(domain="a.example.com", forward_port=80,
                                    forward_host="10.50.0.2")

        assert host.npm_host_id == 101
        assert service.fake_npm.restored == []
        assert service.fake_npm.deleted == []
