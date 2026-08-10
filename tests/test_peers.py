"""Peer allocation, validation, and config rendering."""

from __future__ import annotations

import pytest

from edgekit.services.peers import PeerError, PeerService, validate_extra_allowed_ips
from edgekit.system import wireguard as wg


@pytest.fixture
def service(db_session, config, fake_wg):
    return PeerService(db_session, config)


class TestAddressAllocation:
    def test_first_peer_skips_the_hub_address(self):
        assert wg.next_free_address("10.50.0.0/24", set()) == "10.50.0.2"

    def test_gaps_are_reused(self):
        taken = {"10.50.0.2", "10.50.0.4"}
        assert wg.next_free_address("10.50.0.0/24", taken) == "10.50.0.3"

    def test_exhaustion_raises_rather_than_reassigning(self):
        taken = {f"10.50.0.{i}" for i in range(1, 7)}
        with pytest.raises(wg.WireGuardError, match="No free addresses"):
            wg.next_free_address("10.50.0.0/29", taken)


class TestCreate:
    def test_generates_keys_and_assigns_an_address(self, service):
        peer = service.create("raspberry-pi", description="Home Pi")
        assert peer.address == "10.50.0.2"
        assert peer.private_key
        assert peer.public_key
        assert peer.preshared_key

    def test_accepts_a_client_supplied_public_key_and_stores_no_private_key(self, service):
        key = "MycqDpa23wNgeG4ROMaW2pZ0rjyFqSV3KYWTKf3U+ms="
        peer = service.create("pi", public_key=key)
        assert peer.public_key == key
        assert peer.private_key is None

    def test_rejects_a_malformed_public_key(self, service):
        with pytest.raises(PeerError, match="valid 44-character"):
            service.create("pi", public_key="nope")

    def test_rejects_duplicate_names(self, service):
        service.create("pi")
        with pytest.raises(PeerError, match="already exists"):
            service.create("pi")

    def test_rejects_duplicate_public_keys(self, service):
        key = "MycqDpa23wNgeG4ROMaW2pZ0rjyFqSV3KYWTKf3U+ms="
        service.create("a", public_key=key)
        with pytest.raises(PeerError, match="already registered"):
            service.create("b", public_key=key)

    def test_rejects_an_address_outside_the_subnet(self, service):
        with pytest.raises(PeerError, match="outside the tunnel subnet"):
            service.create("pi", address="192.168.1.5")

    def test_rejects_the_hub_address(self, service):
        with pytest.raises(PeerError, match="reserved for the hub"):
            service.create("pi", address="10.50.0.1")

    def test_rejects_an_address_already_in_use(self, service):
        service.create("a", address="10.50.0.5")
        with pytest.raises(PeerError, match="already assigned"):
            service.create("b", address="10.50.0.5")

    @pytest.mark.parametrize("bad", ["", "-lead", "trail-", "has/slash", "a" * 65])
    def test_rejects_bad_names(self, service, bad):
        with pytest.raises(PeerError):
            service.create(bad)

    def test_accepts_a_single_character_name(self, service):
        assert service.create("a").name == "a"

    def test_surrounding_whitespace_is_trimmed(self, service):
        assert service.create("  pi  ").name == "pi"

    def test_addresses_increment_across_peers(self, service):
        assert [service.create(f"p{i}").address for i in range(3)] == [
            "10.50.0.2",
            "10.50.0.3",
            "10.50.0.4",
        ]


class TestAllowedIps:
    def test_defaults_to_the_peer_slash_32(self, service):
        assert service.create("pi").allowed_ips == "10.50.0.2/32"

    def test_extra_routes_are_appended(self, service):
        peer = service.create("pi", extra_allowed_ips="192.168.1.0/24")
        assert peer.allowed_ips == "10.50.0.2/32, 192.168.1.0/24"

    def test_cidrs_are_normalised(self):
        assert validate_extra_allowed_ips("192.168.1.7/24") == "192.168.1.0/24"

    def test_malformed_cidrs_are_rejected(self):
        with pytest.raises(PeerError, match="not a valid CIDR"):
            validate_extra_allowed_ips("192.168.1.0/99")


class TestRendering:
    def test_interface_config_contains_every_enabled_peer(self, service):
        service.create("pi-one")
        service.create("pi-two")
        rendered = service.render_interface_config()

        assert "[Interface]" in rendered
        assert "Address = 10.50.0.1/24" in rendered
        assert "ListenPort = 51820" in rendered
        assert rendered.count("[Peer]") == 2
        assert "AllowedIPs = 10.50.0.2/32" in rendered
        assert "# pi-one" in rendered

    def test_disabled_peers_are_excluded(self, service, db_session):
        peer = service.create("pi")
        service.create("other")
        service.update(peer.id, enabled=False)
        db_session.flush()

        rendered = service.render_interface_config()
        assert rendered.count("[Peer]") == 1
        assert "10.50.0.2/32" not in rendered

    def test_peer_config_points_back_at_the_hub(self, service):
        peer = service.create("pi")
        rendered = service.render_peer_config(peer)

        assert "Endpoint = 203.0.113.10:51820" in rendered
        assert "PublicKey = vQ8c+XmHJWHtiOAkmiX+zHZAOxyC7W+LgijwGmo14yU=" in rendered
        assert "Address = 10.50.0.2/24" in rendered
        assert "PersistentKeepalive = 25" in rendered
        assert "AllowedIPs = 10.50.0.0/24" in rendered

    def test_peer_config_can_route_only_the_hub(self, service):
        peer = service.create("pi")
        rendered = service.render_peer_config(peer, route_whole_subnet=False)
        assert "AllowedIPs = 10.50.0.1/32" in rendered

    def test_client_key_only_peers_cannot_render_a_config(self, service):
        peer = service.create("pi", public_key="MycqDpa23wNgeG4ROMaW2pZ0rjyFqSV3KYWTKf3U+ms=")
        with pytest.raises(PeerError, match="private key"):
            service.render_peer_config(peer)

    def test_qr_code_is_produced(self, service):
        peer = service.create("pi")
        assert "<svg" in service.render_peer_qr(peer)


class TestLifecycle:
    def test_rotating_keys_replaces_all_key_material(self, service):
        peer = service.create("pi")
        before = (peer.private_key, peer.public_key, peer.preshared_key)
        service.rotate_keys(peer.id)
        assert (peer.private_key, peer.public_key, peer.preshared_key) != before
        assert peer.address == "10.50.0.2", "rotation must not move the peer"

    def test_deleting_a_peer_with_published_hosts_is_refused(self, service, db_session):
        from edgekit.models import ProxyHost

        peer = service.create("pi")
        db_session.add(
            ProxyHost(domain="a.example.com", peer_id=peer.id, forward_host=peer.address,
                      forward_port=3001)
        )
        db_session.flush()

        with pytest.raises(PeerError, match="still serves"):
            service.delete(peer.id)

    def test_sync_writes_the_config_and_applies_it(self, service, fake_wg, config):
        service.create("pi")
        service.sync()

        assert fake_wg == ["wg0"]
        written = wg.config_path("wg0").read_text()
        assert "10.50.0.2/32" in written
