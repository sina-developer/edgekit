"""Config persistence and, most importantly, that secrets never hit disk in plaintext."""

from __future__ import annotations

import stat

import pytest

from edgekit.config import Config, WireGuardConfig
from edgekit.crypto import decrypt, encrypt, is_encrypted


def test_secrets_are_encrypted_on_disk(tmp_path, config):
    path = tmp_path / "config.yaml"
    config.save(path)

    raw = path.read_text()
    assert config.cloudflare.api_token not in raw
    assert config.npm.admin_password not in raw
    assert config.wireguard.private_key not in raw
    assert "enc:" in raw

    # Non-secret values stay readable so the file can be inspected and diffed.
    assert config.server.public_ip in raw
    assert config.cloudflare.zone_name in raw


def test_config_round_trips(tmp_path, config):
    path = tmp_path / "config.yaml"
    config.save(path)

    loaded = Config.load(path)
    assert loaded.cloudflare.api_token == config.cloudflare.api_token
    assert loaded.npm.admin_password == config.npm.admin_password
    assert loaded.wireguard.private_key == config.wireguard.private_key
    assert loaded.server.public_ip == config.server.public_ip


def test_config_file_is_not_world_readable(tmp_path, config):
    path = tmp_path / "config.yaml"
    config.save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"config written with mode {oct(mode)}"


def test_saving_twice_does_not_double_encrypt(tmp_path, config):
    path = tmp_path / "config.yaml"
    config.save(path)
    Config.load(path).save(path)

    assert Config.load(path).cloudflare.api_token == "cf-token"


def test_missing_config_returns_defaults(tmp_path):
    loaded = Config.load(tmp_path / "absent.yaml")
    assert loaded.wireguard.subnet == "10.50.0.0/24"
    assert loaded.configured is False


def test_encrypt_decrypt_are_inverse():
    token = encrypt("hunter2")
    assert is_encrypted(token)
    assert token != "hunter2"
    assert decrypt(token) == "hunter2"


def test_plaintext_passes_through_decrypt():
    """Hand-edited config values must keep working."""
    assert decrypt("plain-value") == "plain-value"


class TestWireGuardConfig:
    def test_hub_takes_the_first_usable_address(self):
        assert WireGuardConfig(subnet="10.50.0.0/24").hub_ip == "10.50.0.1"
        assert WireGuardConfig(subnet="192.168.9.0/24").hub_address == "192.168.9.1/24"

    def test_subnet_is_normalised(self):
        assert WireGuardConfig(subnet="10.50.0.7/24").subnet == "10.50.0.0/24"

    @pytest.mark.parametrize("bad", ["not-a-subnet", "10.50.0.0/31", "::1/64"])
    def test_invalid_subnets_are_rejected(self, bad):
        with pytest.raises(ValueError):
            WireGuardConfig(subnet=bad)

    @pytest.mark.parametrize("bad", [0, 70000, -1])
    def test_invalid_ports_are_rejected(self, bad):
        with pytest.raises(ValueError):
            WireGuardConfig(listen_port=bad)
