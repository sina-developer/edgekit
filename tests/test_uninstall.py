"""Removal deletes what edgekit created, keeps going past failures, and touches nothing else."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from edgekit import uninstall as uninstall_module
from edgekit.services.provision import StepStatus
from edgekit.uninstall import Uninstaller, describe


class FakeCloudflare:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def managed_records(self, zone_id):
        return [{"id": "rec-edgekit", "name": "example.com"}]

    async def delete_dns_record(self, zone_id, record_id):
        self.deleted.append(record_id)


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A fake server: edgekit's files under tmp, every host command replaced by a recorder."""
    layout = {
        "CONFIG_DIR": tmp_path / "etc" / "edgekit",
        "STATE_DIR": tmp_path / "var" / "lib" / "edgekit",
        "LOG_DIR": tmp_path / "var" / "log" / "edgekit",
        "NPM_DIR": tmp_path / "opt" / "nginx-proxy-manager",
        "PROGRAM_DIR": tmp_path / "opt" / "edgekit",
        "ORIGIN_CERT_FILE": tmp_path / "root" / "origin.pem",
        "ORIGIN_KEY_FILE": tmp_path / "root" / "origin.key",
        "PANEL_UNIT": tmp_path / "etc" / "systemd" / "system" / "edgekit-panel.service",
        "SYSCTL_FILE": tmp_path / "etc" / "sysctl.d" / "99-edgekit.conf",
        "PROGRAM_LINK": tmp_path / "usr" / "local" / "bin" / "edgekit",
    }
    for name, path in layout.items():
        monkeypatch.setattr(uninstall_module, name, path)
    for name in ("CONFIG_DIR", "STATE_DIR", "LOG_DIR", "NPM_DIR", "PROGRAM_DIR"):
        (layout[name] / "data").mkdir(parents=True)
        (layout[name] / "data" / "file").write_text("x")
    for name in ("ORIGIN_CERT_FILE", "ORIGIN_KEY_FILE", "PANEL_UNIT", "SYSCTL_FILE"):
        layout[name].parent.mkdir(parents=True, exist_ok=True)
        layout[name].write_text("x")
    layout["PROGRAM_LINK"].parent.mkdir(parents=True)
    layout["PROGRAM_LINK"].symlink_to(layout["PROGRAM_DIR"] / "data" / "file")
    wg_conf = tmp_path / "etc" / "wireguard" / "wg0.conf"
    wg_conf.parent.mkdir(parents=True)
    wg_conf.write_text("[Interface]\n")
    compose_file = layout["NPM_DIR"] / "docker-compose.yml"
    compose_file.write_text("services: {}\n")

    calls: list = []
    cloudflare = FakeCloudflare()

    def remove_panel_unit():
        calls.append("panel")
        layout["PANEL_UNIT"].unlink()

    def record(kind):
        return lambda *args, **kwargs: calls.append((kind, args))

    monkeypatch.setattr("edgekit.service_unit.uninstall", remove_panel_unit)
    monkeypatch.setattr(
        "edgekit.system.firewall.remove_edgekit_rules",
        lambda config: calls.append("firewall") or ["3 iptables rule(s)"],
    )
    monkeypatch.setattr("edgekit.system.dockerx.COMPOSE_FILE", compose_file)
    monkeypatch.setattr(
        "edgekit.system.dockerx.compose", lambda *args, **kw: calls.append(("compose", args))
    )
    monkeypatch.setattr("edgekit.system.wireguard.config_path", lambda interface: wg_conf)
    monkeypatch.setattr("edgekit.system.wireguard.interface_exists", lambda interface: True)
    monkeypatch.setattr(
        "edgekit.system.wireguard.bring_down", lambda interface: calls.append(("wg", interface))
    )
    monkeypatch.setattr("edgekit.services.cloudflare.CloudflareClient", lambda *a, **k: cloudflare)
    monkeypatch.setattr(uninstall_module, "has", lambda binary: True)
    monkeypatch.setattr(uninstall_module, "systemctl", record("systemctl"))
    monkeypatch.setattr(uninstall_module, "run", record("run"))
    monkeypatch.setattr(uninstall_module, "owns_program", lambda: True)
    return SimpleNamespace(layout=layout, wg_conf=wg_conf, calls=calls, cloudflare=cloudflare)


def _by_key(results):
    return {result.key: result for result in results}


async def test_everything_edgekit_created_is_removed(server, config):
    results = await Uninstaller(config).run()

    assert all(r.status is StepStatus.DONE for r in results), [
        (r.key, r.status, r.detail) for r in results
    ]
    for path in [*server.layout.values(), server.wg_conf]:
        assert not path.exists() and not path.is_symlink(), f"{path} survived"
    assert "panel" in server.calls
    assert "firewall" in server.calls
    assert ("wg", "wg0") in server.calls
    compose = next(args for kind, args in (c for c in server.calls if isinstance(c, tuple))
                   if kind == "compose")
    assert "down" in compose and "--rmi" in compose
    assert server.cloudflare.deleted == ["rec-edgekit"]


async def test_a_failing_step_does_not_stop_the_rest(server, config, monkeypatch):
    def locked(config):
        raise RuntimeError("iptables is locked by another process")

    monkeypatch.setattr("edgekit.system.firewall.remove_edgekit_rules", locked)

    results = _by_key(await Uninstaller(config).run())

    assert results["firewall"].status is StepStatus.FAILED
    assert "iptables is locked" in results["firewall"].detail
    assert results["files"].status is StepStatus.DONE
    assert not server.layout["CONFIG_DIR"].exists()


async def test_the_wireguard_keys_go_even_if_the_interface_will_not_come_down(
    server, config, monkeypatch
):
    def stuck(interface):
        raise RuntimeError("wg-quick down failed")

    monkeypatch.setattr("edgekit.system.wireguard.bring_down", stuck)

    results = _by_key(await Uninstaller(config).run())

    assert results["wireguard"].status is StepStatus.FAILED
    assert not server.wg_conf.exists()


async def test_dns_records_can_be_kept(server, config):
    results = _by_key(await Uninstaller(config, keep_dns=True).run())

    assert results["dns"].status is StepStatus.SKIPPED
    assert server.cloudflare.deleted == []


async def test_a_developer_checkout_is_never_deleted(server, config, monkeypatch):
    monkeypatch.setattr(uninstall_module, "owns_program", lambda: False)

    results = _by_key(await Uninstaller(config).run())

    assert results["program"].status is StepStatus.SKIPPED
    assert server.layout["PROGRAM_DIR"].exists()


def test_the_confirmation_lists_dns_only_when_edgekit_would_delete_it(config, monkeypatch):
    monkeypatch.setattr(uninstall_module, "owns_program", lambda: False)
    marker = "the DNS records edgekit created"

    assert any(marker in item for item in describe(config))
    assert not any(marker in item for item in describe(config, keep_dns=True))
    config.cloudflare.api_token = ""
    assert not any(marker in item for item in describe(config))


def test_the_cli_changes_nothing_without_typing_remove(monkeypatch):
    from edgekit.cli import app

    ran: list[int] = []
    monkeypatch.setattr("edgekit.cli.require_root", lambda: None)
    monkeypatch.setattr(uninstall_module.Uninstaller, "run", lambda self: ran.append(1))

    result = CliRunner().invoke(app, ["uninstall"], input="yes\n")

    assert result.exit_code == 1
    assert "Cancelled" in result.output
    assert ran == []
