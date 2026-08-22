"""Host firewall: `edgekit firewall setup` must enable ufw without locking out SSH."""

from __future__ import annotations

from typer.testing import CliRunner

from edgekit.cli import app
from edgekit.system import firewall
from edgekit.system.shell import Result

runner = CliRunner()

ACTIVE_STATUS = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
51820/udp                  ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
80/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
51820/udp (v6)             ALLOW       Anywhere (v6)
"""


def _ok(argv, stdout: str = "") -> Result:
    return Result(tuple(str(a) for a in argv), 0, stdout, "")


def test_enable_allows_ssh_before_turning_ufw_on(config, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv[:2] == ["ufw", "status"]:
            return _ok(argv, ACTIVE_STATUS)
        return _ok(argv)

    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall, "has", lambda binary: binary == "ufw")
    monkeypatch.setattr(firewall, "ensure_forward_policy_accept", lambda: False)

    firewall.enable_host_firewall(config)

    ssh = next(i for i, c in enumerate(calls) if "ufw" in c and "22/tcp" in c)
    enable = next(i for i, c in enumerate(calls) if c[:3] == ["ufw", "--force", "enable"])
    assert ssh < enable, "SSH must be allowed before ufw is enabled"


def test_enable_restarts_docker_after_ufw_rewrites_iptables(config, monkeypatch):
    """ufw enable replaces iptables; Docker's published 80/443 die until docker restarts."""
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv[:2] == ["ufw", "status"]:
            return _ok(argv, ACTIVE_STATUS)
        return _ok(argv)

    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "ensure_forward_policy_accept", lambda: False)

    firewall.enable_host_firewall(config)

    enable = next(i for i, c in enumerate(calls) if c[:3] == ["ufw", "--force", "enable"])
    restart = next(
        i for i, c in enumerate(calls) if c[:3] == ["systemctl", "try-restart", "docker"]
    )
    assert enable < restart


def test_enable_replays_docker_to_wireguard_rules_after_ufw(
    config, monkeypatch, tmp_path
):
    """The docker0↔wg0 rules live outside ufw and are wiped by `ufw enable`."""
    script = tmp_path / "firewall.sh"
    script.write_text("#!/bin/sh\n")
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv[:2] == ["ufw", "status"]:
            return _ok(argv, ACTIVE_STATUS)
        return _ok(argv)

    monkeypatch.setattr(firewall, "FIREWALL_SCRIPT", script)
    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "ensure_forward_policy_accept", lambda: False)

    firewall.enable_host_firewall(config)

    enable = next(i for i, c in enumerate(calls) if c[:3] == ["ufw", "--force", "enable"])
    restart = next(
        i for i, c in enumerate(calls) if c[:3] == ["systemctl", "try-restart", "docker"]
    )
    replay = next(i for i, c in enumerate(calls) if c == [str(script)])
    assert enable < restart < replay


def test_enable_allows_docker_bridge_to_reach_the_panel(config, monkeypatch):
    """ufw default-deny INPUT drops container traffic to 10.50.0.1:8088; 443 then hangs."""
    config.panel.bind = "10.50.0.1"
    config.panel.port = 8088
    config.server.docker_bridge_subnet = "172.17.0.0/16"
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv[:2] == ["ufw", "status"]:
            return _ok(argv, ACTIVE_STATUS)
        return _ok(argv)

    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "ensure_forward_policy_accept", lambda: False)
    monkeypatch.setattr(firewall, "ensure_docker_starts_after_ufw", lambda: False)
    monkeypatch.setattr(firewall, "restore_container_networking", lambda: None)

    firewall.enable_host_firewall(config)

    docker_allow = [
        c for c in calls
        if c[:2] == ["ufw", "allow"] and "172.17.0.0/16" in c and "8088" in c
    ]
    assert docker_allow, calls
    assert "10.50.0.1" in docker_allow[0]
    assert ["ufw", "allow", "8088/tcp"] not in calls
    enable = next(i for i, c in enumerate(calls) if c[:3] == ["ufw", "--force", "enable"])
    assert calls.index(docker_allow[0]) < enable


def test_check_does_not_treat_docker_only_panel_allow_as_public(config, monkeypatch):
    status = ACTIVE_STATUS + "8088/tcp                   ALLOW       172.17.0.0/16\n"
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "run", lambda argv, **k: _ok(argv, status))
    report = firewall.check_host_firewall(config)
    panel = next(p for p in report.ports if p.port == 8088)
    assert panel.allowed is False
    assert panel.ok is True
    assert report.ok is True


def test_enable_opens_required_ports_and_skips_admin_and_panel(config, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv[:2] == ["ufw", "status"]:
            return _ok(argv, ACTIVE_STATUS)
        return _ok(argv)

    monkeypatch.setattr(firewall, "run", fake_run)
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "ensure_forward_policy_accept", lambda: False)

    firewall.enable_host_firewall(config)

    allowed = [" ".join(c) for c in calls if c[:2] == ["ufw", "allow"]]
    blob = "\n".join(allowed)
    assert "22/tcp" in blob
    assert "51820/udp" in blob
    assert "80/tcp" in blob
    assert "443/tcp" in blob
    assert "8181" not in blob
    assert "8088" not in blob


def test_check_reports_inactive_ufw(config, monkeypatch):
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(
        firewall, "run", lambda argv, **k: _ok(argv, "Status: inactive\n")
    )
    report = firewall.check_host_firewall(config)
    assert report.installed is True
    assert report.active is False
    assert report.ok is False


def test_check_passes_when_open_ports_are_allowed_and_closed_are_not(config, monkeypatch):
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "run", lambda argv, **k: _ok(argv, ACTIVE_STATUS))
    report = firewall.check_host_firewall(config)
    assert report.active is True
    assert report.ok is True
    by_port = {(p.protocol, p.port): p for p in report.ports}
    assert by_port[("tcp", 22)].allowed is True
    assert by_port[("udp", 51820)].allowed is True
    assert by_port[("tcp", 8181)].allowed is False
    assert by_port[("tcp", 8088)].ok is True


def test_check_fails_when_wireguard_port_is_missing(config, monkeypatch):
    status = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
"""
    monkeypatch.setattr(firewall, "has", lambda binary: True)
    monkeypatch.setattr(firewall, "run", lambda argv, **k: _ok(argv, status))
    report = firewall.check_host_firewall(config)
    wg = next(p for p in report.ports if p.port == 51820)
    assert wg.allowed is False
    assert report.ok is False


def test_ensure_forward_policy_accept_rewrites_drop(tmp_path):
    path = tmp_path / "ufw"
    path.write_text('DEFAULT_FORWARD_POLICY="DROP"\nDEFAULT_INPUT_POLICY="DROP"\n')
    changed = firewall.ensure_forward_policy_accept(path)
    assert changed is True
    assert 'DEFAULT_FORWARD_POLICY="ACCEPT"' in path.read_text()
    assert 'DEFAULT_INPUT_POLICY="DROP"' in path.read_text()


def test_firewall_setup_command_prints_the_result(monkeypatch, config):
    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.require_configured", lambda: config)
    monkeypatch.setattr(
        "edgekit.cli.firewall.enable_host_firewall",
        lambda cfg: firewall.HostFirewallReport(
            installed=True,
            active=True,
            status_text=ACTIVE_STATUS,
            ports=[
                firewall.PortCheck("tcp", 22, "SSH", "open", True, True),
                firewall.PortCheck("udp", 51820, "WireGuard", "open", True, True),
            ],
        ),
    )
    result = runner.invoke(app, ["firewall", "setup"])
    assert result.exit_code == 0, result.output
    assert "22" in result.output
    assert "51820" in result.output


def test_firewall_check_command_prints_missing_ports(monkeypatch, config):
    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.require_configured", lambda: config)
    monkeypatch.setattr(
        "edgekit.cli.firewall.check_host_firewall",
        lambda cfg: firewall.HostFirewallReport(
            installed=True,
            active=True,
            status_text="Status: active\n",
            ports=[
                firewall.PortCheck("udp", 51820, "WireGuard tunnel", "open", False, False),
            ],
        ),
    )
    result = runner.invoke(app, ["firewall", "check"])
    assert result.exit_code == 1
    assert "51820" in result.output
