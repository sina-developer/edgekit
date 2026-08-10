"""Provisioner step semantics, generated artifacts, and health-check reporting."""

from __future__ import annotations

import pytest

from edgekit.services.health import Level
from edgekit.services.provision import (
    Provisioner,
    ProvisionError,
    SkipStep,
    StepStatus,
    _looks_like_ipv4,
)
from edgekit.system import firewall


class TestStepRunner:
    async def test_a_successful_step_is_recorded_done(self, config):
        provisioner = Provisioner(config)
        result = await provisioner._step("k", "Title", lambda: "detail here")

        assert result.status is StepStatus.DONE
        assert result.detail == "detail here"

    async def test_a_raised_skip_is_recorded_skipped_not_failed(self, config):
        def skip():
            raise SkipStep("disabled by flag")

        result = await Provisioner(config)._step("k", "Title", skip)
        assert result.status is StepStatus.SKIPPED
        assert "disabled by flag" in result.detail

    async def test_a_failure_carries_the_message_through(self, config):
        def boom():
            raise ProvisionError("docker is not installed")

        result = await Provisioner(config)._step("k", "Title", boom)
        assert result.status is StepStatus.FAILED
        assert "docker is not installed" in result.detail

    async def test_async_steps_are_awaited(self, config):
        async def work():
            return "async detail"

        result = await Provisioner(config)._step("k", "Title", work)
        assert result.status is StepStatus.DONE
        assert result.detail == "async detail"

    async def test_a_broken_listener_does_not_fail_the_step(self, config):
        def listener(_step):
            raise RuntimeError("the UI blew up")

        result = await Provisioner(config, on_event=listener)._step("k", "T", lambda: "ok")
        assert result.status is StepStatus.DONE

    async def test_events_are_emitted_for_running_then_terminal(self, config):
        seen = []
        provisioner = Provisioner(config, on_event=lambda s: seen.append(s.status))
        await provisioner._step("k", "T", lambda: "ok")
        assert seen == [StepStatus.RUNNING, StepStatus.DONE]


class TestHubKeys:
    def test_existing_keys_are_reused(self, config):
        before = config.wireguard.private_key
        detail = Provisioner(config).step_hub_keys()

        assert config.wireguard.private_key == before
        assert "reused" in detail

    def test_a_missing_public_key_is_derived_not_regenerated(self, config, monkeypatch):
        from edgekit.system import wireguard as wg

        monkeypatch.setattr(wg, "derive_public_key", lambda private: "derived-key")
        config.wireguard.public_key = ""

        detail = Provisioner(config).step_hub_keys()

        assert config.wireguard.public_key == "derived-key"
        assert "derived" in detail

    def test_keys_are_generated_when_absent(self, config, fake_wg):
        config.wireguard.private_key = ""
        config.wireguard.public_key = ""

        Provisioner(config).step_hub_keys()

        assert config.wireguard.private_key
        assert config.wireguard.public_key


class TestFlags:
    async def test_skip_packages_skips_installation_steps(self, config):
        provisioner = Provisioner(config, skip_packages=True)
        for fn in (provisioner.step_base_packages, provisioner.step_install_wireguard):
            with pytest.raises(SkipStep):
                fn()

    async def test_skip_cloudflare_skips_the_zone_step(self, config):
        provisioner = Provisioner(config, skip_cloudflare=True)
        with pytest.raises(SkipStep):
            await provisioner.step_cloudflare_zone()

    async def test_cloudflare_steps_skip_when_the_integration_is_off(self, config):
        config.cloudflare.enabled = False
        provisioner = Provisioner(config)
        with pytest.raises(SkipStep):
            await provisioner.step_cloudflare_zone()

    async def test_an_enabled_zone_without_a_token_is_an_error_not_a_skip(self, config):
        config.cloudflare.api_token = ""
        with pytest.raises(ProvisionError, match="no API token"):
            await Provisioner(config).step_cloudflare_zone()


class TestPublishPanel:
    async def test_skips_without_a_zone(self, config):
        config.cloudflare.zone_name = ""
        config.panel.bind = "10.50.0.1"
        with pytest.raises(SkipStep, match="no zone"):
            await Provisioner(config).step_publish_panel()

    async def test_skips_when_panel_is_loopback_only(self, config):
        config.panel.bind = "127.0.0.1"
        with pytest.raises(SkipStep, match="loopback"):
            await Provisioner(config).step_publish_panel()

    async def test_creates_edgekit_host_on_the_hub(self, config, clean_db, monkeypatch):
        from edgekit.services import hosts as hosts_module

        config.panel.bind = "10.50.0.1"
        config.panel.port = 8088
        created: dict = {}

        async def fake_create(self, **kwargs):
            created.update(kwargs)
            host = type("H", (), {
                "domain": kwargs["domain"],
                "forward_host": kwargs["forward_host"],
                "forward_port": kwargs["forward_port"],
            })()
            return host

        monkeypatch.setattr(hosts_module.HostService, "create", fake_create)
        detail = await Provisioner(config).step_publish_panel()

        assert created["domain"] == "edgekit.example.com"
        assert created["forward_host"] == "10.50.0.1"
        assert created["forward_port"] == 8088
        assert "edgekit.example.com" in detail

    async def test_updates_existing_panel_host_target(self, config, clean_db, monkeypatch):
        from edgekit.db import session_scope
        from edgekit.models import ProxyHost
        from edgekit.services import hosts as hosts_module

        config.panel.bind = "10.50.0.1"
        config.panel.port = 8088
        with session_scope() as session:
            session.add(
                ProxyHost(
                    domain="edgekit.example.com",
                    forward_host="10.50.0.9",
                    forward_port=9999,
                    scheme="http",
                )
            )
        updated: dict = {}

        async def fake_update(self, host_id, **kwargs):
            updated["host_id"] = host_id
            updated.update(kwargs)
            return self.get(host_id)

        monkeypatch.setattr(hosts_module.HostService, "update", fake_update)
        detail = await Provisioner(config).step_publish_panel()

        assert updated["forward_host"] == "10.50.0.1"
        assert updated["forward_port"] == 8088
        assert "updated" in detail


class TestFirewallArtifacts:
    def test_the_generated_script_checks_before_it_appends(self, tmp_path, monkeypatch):
        monkeypatch.setattr(firewall, "FIREWALL_SCRIPT", tmp_path / "firewall.sh")
        monkeypatch.setattr(firewall, "FIREWALL_UNIT", tmp_path / "unit.service")

        firewall.write_rules(
            docker_subnet="172.17.0.0/16", wg_subnet="10.50.0.0/24", wg_if="wg0"
        )
        script = (tmp_path / "firewall.sh").read_text()

        # `iptables -C` before `-A` is what makes replaying the script idempotent.
        assert 'iptables -t "$table" -C "$chain" "$@"' in script
        assert "172.17.0.0/16" in script
        assert "10.50.0.0/24" in script
        assert "MASQUERADE" in script
        assert "ESTABLISHED,RELATED" in script

    def test_the_generated_script_is_valid_shell(self, tmp_path, monkeypatch):
        import subprocess

        monkeypatch.setattr(firewall, "FIREWALL_SCRIPT", tmp_path / "firewall.sh")
        monkeypatch.setattr(firewall, "FIREWALL_UNIT", tmp_path / "unit.service")
        firewall.write_rules(
            docker_subnet="172.17.0.0/16", wg_subnet="10.50.0.0/24", wg_if="wg0"
        )

        result = subprocess.run(
            ["sh", "-n", str(tmp_path / "firewall.sh")], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr

    def test_the_unit_runs_after_docker(self, tmp_path, monkeypatch):
        monkeypatch.setattr(firewall, "FIREWALL_SCRIPT", tmp_path / "firewall.sh")
        monkeypatch.setattr(firewall, "FIREWALL_UNIT", tmp_path / "unit.service")
        monkeypatch.setattr(firewall, "systemctl", lambda *a, **k: None)

        firewall.write_rules(
            docker_subnet="172.17.0.0/16", wg_subnet="10.50.0.0/24", wg_if="wg0"
        )
        unit = (tmp_path / "unit.service").read_text()

        assert "After=network-online.target docker.service wg-quick@wg0.service" in unit
        assert "RemainAfterExit=yes" in unit


class TestComposeRendering:
    def test_the_admin_port_is_bound_to_loopback(self, config):
        from edgekit.rendering import render

        rendered = render(
            "docker-compose.yml.j2",
            image=config.npm.image,
            container_name=config.npm.container_name,
            http_port=80,
            https_port=443,
            admin_port=8181,
            admin_bind="127.0.0.1",
        )

        assert '"127.0.0.1:8181:81"' in rendered
        assert '"80:80"' in rendered
        assert '"443:443"' in rendered
        # An unqualified admin mapping would publish the NPM UI to the internet.
        assert '"8181:81"' not in rendered


class TestPublicIpDetection:
    @pytest.mark.parametrize("value", ["1.2.3.4", "203.0.113.10", "255.255.255.255"])
    def test_accepts_valid_addresses(self, value):
        assert _looks_like_ipv4(value)

    @pytest.mark.parametrize(
        "value", ["", "not-an-ip", "1.2.3", "1.2.3.4.5", "256.1.1.1", "<html>error</html>"]
    )
    def test_rejects_everything_else(self, value):
        assert not _looks_like_ipv4(value)


class TestHealthChecks:
    async def test_missing_forwarding_is_a_failure_with_a_remedy(self, config, monkeypatch):
        from edgekit.services import health
        from edgekit.system import sysctl

        monkeypatch.setattr(sysctl, "verify", lambda: {"net.ipv4.ip_forward": False})
        check = health._check_forwarding()

        assert check.level is Level.FAIL
        assert "sysctl" in check.remedy

    async def test_enabled_forwarding_passes(self, config, monkeypatch):
        from edgekit.services import health
        from edgekit.system import sysctl

        monkeypatch.setattr(sysctl, "verify", lambda: {"net.ipv4.ip_forward": True})
        assert health._check_forwarding().level is Level.OK

    def test_the_cloud_firewall_reminder_names_every_port(self, config):
        from edgekit.services import health

        check = health.cloud_firewall_reminder(config)

        assert check.level is Level.WARN
        assert "51820" in check.remedy
        assert "80" in check.remedy
        assert "443" in check.remedy

    def test_a_report_with_a_failure_is_not_ok(self):
        from edgekit.services.health import Check, HealthReport

        report = HealthReport([
            Check("a", "A", Level.OK),
            Check("b", "B", Level.WARN),
            Check("c", "C", Level.FAIL),
        ])

        assert report.ok is False
        assert len(report.failures) == 1
        assert len(report.warnings) == 1

    def test_warnings_alone_do_not_fail_a_report(self):
        from edgekit.services.health import Check, HealthReport

        assert HealthReport([Check("a", "A", Level.WARN)]).ok is True
