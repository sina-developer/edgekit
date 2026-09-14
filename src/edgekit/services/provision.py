"""The provisioner: the guide, encoded as idempotent steps.

Every step is safe to re-run. That is the property that makes this usable across many
servers and across repeated runs on the same server — a partially provisioned host converges
rather than erroring or duplicating state. Steps report progress through a callback so the
CLI and the panel can both render the same run.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from sqlalchemy import select

from ..config import Config
from ..db import session_scope
from ..models import AuditLog, ProxyHost
from ..paths import NPM_DIR, ensure_dirs
from ..rendering import render
from ..system import dockerx, firewall, packages, sysctl
from ..system import wireguard as wg
from ..system.shell import is_root
from . import certificates, health
from .hosts import HostService
from .npm import NPMClient
from .peers import PeerService

log = logging.getLogger("edgekit.provision")


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class StepResult:
    key: str
    title: str
    status: StepStatus
    detail: str = ""


@dataclass
class ProvisionReport:
    results: list[StepResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(r.status is StepStatus.FAILED for r in self.results)

    @property
    def failures(self) -> list[StepResult]:
        return [r for r in self.results if r.status is StepStatus.FAILED]


EventCallback = Callable[[StepResult], None] | None


class ProvisionError(RuntimeError):
    pass


class SkipStep(Exception):
    """Raised inside a step to record it as skipped rather than failed."""


#: Steps whose failure makes everything after them meaningless.
_FATAL_STEPS = {"preflight", "wireguard_keys", "wireguard_up"}

#: The steps that decide what browsers get over HTTPS — all `edgekit ssl mode` needs to rerun.
TLS_STEPS = (
    "cloudflare_zone",
    "cloudflare_dns",
    "cloudflare_ssl",
    "origin_cert",
    "attach_cert",
    "panel_host",
    "verify_https",
    "persist",
)


class Provisioner:
    """Runs the full setup. Construct with a validated :class:`Config` and call :meth:`run`."""

    def __init__(
        self,
        config: Config,
        *,
        skip_packages: bool = False,
        skip_docker: bool = False,
        skip_cloudflare: bool = False,
        on_event: EventCallback = None,
    ) -> None:
        self.config = config
        self.skip_packages = skip_packages
        self.skip_docker = skip_docker
        self.skip_cloudflare = skip_cloudflare
        self.on_event = on_event
        self.report = ProvisionReport()

    # ---------------------------------------------------------------- runner

    def _emit(self, result: StepResult) -> None:
        if self.on_event:
            try:
                self.on_event(result)
            except Exception:  # noqa: BLE001 - a broken listener must not fail provisioning
                log.exception("provision event listener raised")

    async def _step(
        self, key: str, title: str, fn: Callable[[], Any | Awaitable[Any]]
    ) -> StepResult:
        self._emit(StepResult(key, title, StepStatus.RUNNING))
        try:
            outcome = fn()
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
        except SkipStep as skip:
            result = StepResult(key, title, StepStatus.SKIPPED, str(skip))
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator verbatim
            log.exception("step %s failed", key)
            result = StepResult(key, title, StepStatus.FAILED, str(exc))
        else:
            result = StepResult(key, title, StepStatus.DONE, str(outcome or ""))

        self.report.results.append(result)
        self._emit(result)
        return result

    async def run(self, only: Iterable[str] | None = None) -> ProvisionReport:
        """Run every step, or just the keys in ``only``, in the usual order."""
        wanted = set(only) if only is not None else None
        certificate_title = (
            "Install origin certificate"
            if self.config.dns_proxied
            else "Issue Let's Encrypt certificate"
        )
        steps: list[tuple[str, str, Callable[[], Any]]] = [
            ("preflight", "Preflight checks", self.step_preflight),
            ("packages", "Install base packages", self.step_base_packages),
            ("wireguard_install", "Install WireGuard", self.step_install_wireguard),
            ("wireguard_keys", "Generate hub keypair", self.step_hub_keys),
            ("wireguard_up", "Configure and start wg0", self.step_wireguard_interface),
            ("sysctl", "Enable IP forwarding", self.step_sysctl),
            ("docker_install", "Install Docker", self.step_install_docker),
            ("host_nginx", "Free ports 80/443", self.step_stop_host_nginx),
            ("npm_deploy", "Deploy Nginx Proxy Manager", self.step_deploy_npm),
            ("npm_bootstrap", "Secure the NPM admin account", self.step_bootstrap_npm),
            ("firewall", "Bridge Docker to WireGuard", self.step_firewall),
            ("cloudflare_zone", "Verify Cloudflare zone", self.step_cloudflare_zone),
            ("cloudflare_dns", "Publish DNS records", self.step_cloudflare_dns),
            ("cloudflare_ssl", "Set SSL mode to Full (strict)", self.step_cloudflare_ssl),
            ("origin_cert", certificate_title, self.step_certificate),
            ("attach_cert", "Attach certificate to proxy hosts", self.step_attach_certificate),
            ("panel_host", "Publish panel at edgekit.<zone>", self.step_publish_panel),
            ("verify_https", "Verify HTTPS as browsers see it", self.step_verify_https),
            ("persist", "Save configuration", self.step_persist),
        ]

        for key, title, fn in steps:
            if wanted is not None and key not in wanted:
                continue
            result = await self._step(key, title, fn)
            if result.status is StepStatus.FAILED and key in _FATAL_STEPS:
                log.error("aborting: %s is required and failed", key)
                break

        with session_scope() as session:
            session.add(
                AuditLog(
                    action="provision.run",
                    target=self.config.server.public_ip,
                    detail=f"{len(self.report.results)} steps, "
                           f"{len(self.report.failures)} failed",
                    success=self.report.ok,
                )
            )
        return self.report

    # ---------------------------------------------------------------- steps

    def step_preflight(self) -> str:
        if not is_root():
            raise ProvisionError("edgekit must provision as root (use sudo)")

        ensure_dirs()
        info = packages.require_debian_like()

        if not self.config.server.public_ip:
            detected = detect_public_ip()
            if not detected:
                raise ProvisionError(
                    "Could not determine this server's public IP. Set server.public_ip in "
                    "/etc/edgekit/config.yaml and re-run."
                )
            self.config.server.public_ip = detected
        if not self.config.server.hostname:
            self.config.server.hostname = socket.gethostname()
        # Under sudo, SUDO_USER is the real login account — the one that can actually ssh in.
        self.config.server.ssh_user = os.environ.get("SUDO_USER") or "root"

        return (
            f"{info.get('PRETTY_NAME', 'Linux')}, public IP {self.config.server.public_ip}"
        )

    def step_base_packages(self) -> str:
        if self.skip_packages:
            raise SkipStep("--skip-packages")
        packages.install_base()
        return "base packages present"

    def step_install_wireguard(self) -> str:
        if self.skip_packages:
            raise SkipStep("--skip-packages")
        packages.install_wireguard()
        return packages.wireguard_version() or "installed"

    def step_hub_keys(self) -> str:
        cfg = self.config.wireguard
        if cfg.private_key and cfg.public_key:
            return "existing keypair reused"
        if cfg.private_key and not cfg.public_key:
            cfg.public_key = wg.derive_public_key(cfg.private_key)
            return "public key derived from existing private key"
        keypair = wg.generate_keypair()
        cfg.private_key, cfg.public_key = keypair.private_key, keypair.public_key
        return f"new keypair, public key {cfg.public_key}"

    def step_wireguard_interface(self) -> str:
        cfg = self.config.wireguard
        with session_scope() as session:
            peers = PeerService(session, self.config)
            wg.write_config(cfg.interface, peers.render_interface_config())
            peer_count = len([p for p in peers.list() if p.enabled])

        wg.bring_up(cfg.interface)
        wg.apply_config(cfg.interface)
        wg.enable_at_boot(cfg.interface)
        return f"{cfg.interface} up on {cfg.hub_address} with {peer_count} peer(s)"

    def step_sysctl(self) -> str:
        sysctl.apply()
        failed = [k for k, ok in sysctl.verify().items() if not ok]
        if failed:
            raise ProvisionError(f"could not set: {', '.join(failed)}")
        return "net.ipv4.ip_forward = 1"

    def step_install_docker(self) -> str:
        if self.skip_packages or self.skip_docker:
            raise SkipStep("skipped by flag")
        packages.install_docker()
        engine, compose = packages.docker_versions()
        return f"{engine or 'docker'} / {compose or 'compose'}"

    def step_stop_host_nginx(self) -> str:
        if self.skip_docker:
            raise SkipStep("--skip-docker")
        acted = packages.stop_host_nginx()
        return "host nginx stopped and disabled" if acted else "no host nginx running"

    def step_deploy_npm(self) -> str:
        if self.skip_docker or not self.config.npm.enabled:
            raise SkipStep("NPM deployment disabled")

        npm = self.config.npm
        content = render(
            "docker-compose.yml.j2",
            image=npm.image,
            container_name=npm.container_name,
            http_port=npm.http_port,
            https_port=npm.https_port,
            admin_port=npm.admin_port,
            admin_bind=npm.admin_bind,
        )
        dockerx.write_compose_file(content)
        dockerx.validate()
        dockerx.up()

        state = dockerx.container_state(npm.container_name)
        if not state.get("running"):
            raise ProvisionError(
                f"container {npm.container_name} is not running "
                f"({state.get('status')}). Recent logs:\n"
                + dockerx.logs(npm.container_name, 30)
            )
        return f"{npm.container_name} running from {NPM_DIR}"

    async def step_bootstrap_npm(self) -> str:
        if self.skip_docker or not self.config.npm.enabled:
            raise SkipStep("NPM deployment disabled")

        npm = self.config.npm
        if not (npm.admin_email and npm.admin_password):
            raise ProvisionError("NPM admin email and password must be set before provisioning")

        async with NPMClient(npm.api_base, npm.admin_email, npm.admin_password) as client:
            await client.wait_until_ready()
            rotated = await client.bootstrap_admin(npm.admin_email, npm.admin_password)
            user = await client.me()

        return (
            f"admin is {user.get('email', npm.admin_email)}"
            + (" (default credentials rotated)" if rotated else "")
        )

    def step_firewall(self) -> str:
        if self.skip_docker:
            raise SkipStep("--skip-docker")

        # The bridge NPM is on, not the default one: Compose puts it on its own project
        # network, and rules naming docker0/172.17.0.0/16 match nothing.
        bridge = firewall.detect_proxy_bridge(self.config)
        docker_subnet = bridge.subnet
        docker_if = bridge.interface
        self.config.server.docker_bridge_subnet = docker_subnet
        wg_if = self.config.wireguard.interface
        wg_subnet = self.config.wireguard.subnet

        firewall.write_rules(
            docker_subnet=docker_subnet,
            wg_subnet=wg_subnet,
            wg_if=wg_if,
            docker_if=docker_if,
        )
        firewall.apply_rules()

        if not firewall.rules_present(
            docker_subnet=docker_subnet, wg_subnet=wg_subnet, wg_if=wg_if, docker_if=docker_if
        ):
            raise ProvisionError("forwarding rules did not apply; check `iptables -S`")

        opened = firewall.open_host_ports(
            wg_port=self.config.wireguard.listen_port,
            http_port=self.config.npm.http_port,
            https_port=self.config.npm.https_port,
        )
        panel = firewall.allow_docker_to_panel(self.config)
        suffix = f"; ufw opened {', '.join(opened)}" if opened else ""
        if panel:
            suffix += f"; panel reachable from {', '.join(panel)}"
        return f"{bridge.network}: {docker_if} ({docker_subnet}) -> {wg_if} ({wg_subnet}){suffix}"

    async def step_cloudflare_zone(self) -> str:
        cf = self.config.cloudflare
        if self.skip_cloudflare:
            raise SkipStep("--skip-cloudflare")
        if not cf.zone_name:
            raise SkipStep("no domain configured")
        if not (cf.enabled and cf.api_token):
            # Not a skip: without the API, nothing keeps DNS proxy status and the SSL mode in
            # step with the certificate, and the mismatch is a certificate browsers reject.
            raise ProvisionError(
                "Cloudflare is not configured: no API token is stored. edgekit sets DNS proxy "
                "status and the SSL mode to match the certificate it installs. Store one with "
                f"`edgekit cloudflare token --zone {cf.zone_name}`."
            )

        from .cloudflare import CloudflareClient

        async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
            await client.verify_token()
            cf.zone_id = await client.get_zone_id(cf.zone_name)
            # Fail here, with a precise list of missing permissions, rather than letting the
            # DNS and SSL steps each fail separately with an opaque 403.
            report = await client.require_zone_permissions(cf.zone_id)

        optional = [c.permission for c in report if not c.required and not c.ok]
        suffix = f"; cannot {', '.join(optional)}" if optional else ""
        return f"zone {cf.zone_name} = {cf.zone_id}{suffix}"

    async def step_cloudflare_dns(self) -> str:
        cf = self.config.cloudflare
        if self.skip_cloudflare or not (cf.enabled and cf.zone_id):
            raise SkipStep("Cloudflare integration disabled")

        from .cloudflare import CloudflareClient

        ip = self.config.server.public_ip
        proxied = self.config.dns_proxied
        names = [cf.zone_name, f"*.{cf.zone_name}"]
        async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
            for name in names:
                await client.upsert_a_record(cf.zone_id, name, ip, proxied=proxied)
            # Every other record pointing here too — including ones added by hand, which is
            # how a DNS-only hostname ends up serving the Origin certificate to browsers.
            changed = await client.reconcile_proxy_status(cf.zone_id, ip, proxied=proxied)
        label = "proxied" if proxied else "DNS only"
        detail = f"{', '.join(names)} -> {ip} ({label})"
        if changed:
            detail += f"; switched to {label}: {', '.join(changed)}"
        return detail

    async def step_cloudflare_ssl(self) -> str:
        cf = self.config.cloudflare
        if self.skip_cloudflare or not (cf.enabled and cf.zone_id):
            raise SkipStep("Cloudflare integration disabled")
        if not self.config.dns_proxied:
            raise SkipStep("direct mode — visitors do not pass through Cloudflare's TLS")

        from .cloudflare import CloudflareClient

        async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
            mode = await client.set_ssl_mode(cf.zone_id, "strict")
        return f"SSL mode = {mode}"

    async def step_certificate(self) -> str:
        """Install the certificate the TLS mode calls for."""
        if self.skip_docker:
            raise SkipStep("--skip-docker")
        if self.config.dns_proxied:
            return await self._install_origin_certificate()
        return await self._install_letsencrypt()

    async def _install_letsencrypt(self) -> str:
        if self.skip_cloudflare:
            raise ProvisionError(
                "direct mode issues its certificate through a Cloudflare DNS challenge, so it "
                "cannot run with --skip-cloudflare"
            )
        with session_scope() as session:
            outcome = await certificates.install_letsencrypt(session, self.config)
        return (
            f"{outcome['status']} {outcome['hostnames']} as NPM id {outcome['certificate_id']}"
            + (f", expires {outcome['expires'][:10]}" if outcome["expires"] else "")
        )

    async def _install_origin_certificate(self) -> str:
        """Install the origin certificate into NPM.

        Prefers the certificate the operator supplied, which is the normal path — creating
        one in the Cloudflare dashboard is a single one-time action. Falls back to issuing
        via the API only when that automation has been explicitly enabled.
        """
        tls = self.config.tls
        if tls.present:
            # The stored pair is validated on the way in, but config.yaml can be edited by
            # hand and a certificate that was valid at setup expires on its own schedule.
            # Installing a bad one here is silent until Cloudflare answers 525.
            info = certificates.validate_pair(tls.certificate, tls.certificate_key)
            with session_scope() as session:
                domains = [h.domain for h in session.scalars(select(ProxyHost))]
                warnings = certificates.coverage_warnings(
                    info, self.config.cloudflare.zone_name, domains
                )
                outcome = await certificates.install_manual_certificate(
                    session, self.config, tls.certificate, tls.certificate_key, name=tls.name
                )
            for warning in warnings:
                log.warning("origin certificate: %s", warning)
            detail = (
                f"unchanged, NPM id {outcome['certificate_id']}"
                if outcome["status"] == "unchanged"
                else (
                    f"installed {', '.join(info.hostnames)} as NPM id "
                    f"{outcome['certificate_id']}"
                )
            )
            return f"{detail}, expires {info.not_after.date()}" + (
                " — " + "; ".join(warnings) if warnings else ""
            )

        cf = self.config.cloudflare
        if self.skip_cloudflare or not (cf.enabled and cf.zone_id):
            raise SkipStep("no certificate supplied — add one with `edgekit cert install`")

        with session_scope() as session:
            outcome = await certificates.issue_and_install(session, self.config)
        return (
            f"{outcome['status']}, NPM certificate id {outcome['certificate_id']}"
            + (f", expires {outcome['expires'][:10]}" if outcome.get("expires") else "")
        )

    async def step_publish_panel(self) -> str:
        """Publish the management panel at edgekit.<zone> via NPM.

        The panel listens on the WireGuard hub IP so the NPM container can reach it.
        Requires a zone name; origin certificate should already be installed when possible.
        """
        if self.skip_docker or not self.config.npm.enabled:
            raise SkipStep("NPM disabled")

        domain = self.config.public_panel_domain
        if not domain:
            raise SkipStep("no zone configured — set cloudflare.zone_name to publish the panel")

        bind = self.config.panel.bind
        if bind in ("127.0.0.1", "localhost"):
            raise SkipStep(
                "panel bound to loopback — set panel.bind to the WireGuard hub IP "
                "(or omit EDGEKIT_PANEL_BIND) so NPM can reach it"
            )

        port = self.config.panel.port
        with session_scope() as session:
            existing = session.scalar(select(ProxyHost).where(ProxyHost.domain == domain))
            service = HostService(session, self.config)
            if existing:
                # Keep target aligned with the current panel bind/port across re-provisions.
                if existing.forward_host != bind or existing.forward_port != port:
                    await service.update(
                        existing.id,
                        peer_id=None,
                        forward_host=bind,
                        forward_port=port,
                        manage_dns=True,
                        actor="provision",
                    )
                    return f"{domain} updated -> {bind}:{port}"
                return f"{domain} already published -> {bind}:{port}"

            host = await service.create(
                domain=domain,
                forward_port=port,
                forward_host=bind,
                manage_dns=True,
                actor="provision",
            )
            return f"{host.domain} -> {host.forward_host}:{host.forward_port}"

    async def step_attach_certificate(self) -> str:
        if self.skip_docker or not self.config.npm.enabled:
            raise SkipStep("NPM disabled")
        with session_scope() as session:
            service = HostService(session, self.config)
            if service.certificate_id() is None:
                raise SkipStep("no certificate installed")
            moved = await service.attach_certificate()
        return f"moved {', '.join(moved)}" if moved else "every proxy host already uses it"

    #: How long to wait out a DNS change applied moments ago. Cloudflare's own resolvers see a
    #: proxy toggle within seconds; others hold the old answer for its TTL.
    VERIFY_WINDOW = 120.0
    VERIFY_INTERVAL = 10.0

    async def step_verify_https(self) -> str:
        """Connect to every hostname as a browser would, and fail on what a browser rejects.

        Everything before this checks a component. This checks the outcome — the certificate a
        visitor is actually shown — which is the only thing that proves DNS, the SSL mode and
        the certificate agree with each other.
        """
        if self.skip_docker or not self.config.npm.enabled:
            raise SkipStep("NPM disabled")
        with session_scope() as session:
            domains = sorted({h.domain for h in session.scalars(select(ProxyHost))})
        if not domains:
            raise SkipStep("no proxy hosts to check")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.VERIFY_WINDOW
        pending = domains
        results: dict[str, health.Check] = {}
        while True:
            probes = await asyncio.gather(
                *(asyncio.to_thread(health.probe_public_https, domain) for domain in pending)
            )
            retry: list[str] = []
            for probe in probes:
                check, worth_retrying = health.assess_public(probe, self.config)
                results[probe.domain] = check
                if worth_retrying and check.level is not health.Level.OK:
                    retry.append(probe.domain)
            if not retry or loop.time() + self.VERIFY_INTERVAL > deadline:
                break
            log.info("waiting for DNS to settle on %s", ", ".join(retry))
            await asyncio.sleep(self.VERIFY_INTERVAL)
            pending = retry

        failures = [c for c in results.values() if c.level is health.Level.FAIL]
        if failures:
            raise ProvisionError(
                "\n".join(f"{c.title}: {c.detail}\n  {c.remedy}" for c in failures)
            )
        trusted = [d for d, c in results.items() if c.level is health.Level.OK]
        detail = f"trusted on {', '.join(trusted)}" if trusted else "no host answered cleanly"
        warnings = [c for c in results.values() if c.level is health.Level.WARN]
        if warnings:
            detail += "; " + "; ".join(
                f"{c.title.removeprefix('Public ')}: {c.detail}" for c in warnings
            )
        return detail

    def step_persist(self) -> str:
        self.config.save()
        return "written to /etc/edgekit/config.yaml"


def detect_public_ip(timeout: float = 5.0) -> str | None:
    """Discover the server's public IPv4.

    Cloud metadata first (authoritative, no internet round-trip), then public reflectors.
    """
    metadata_sources = (
        # AWS IMDSv2 requires a token; IMDSv1 still answers on most images.
        ("http://169.254.169.254/latest/meta-data/public-ipv4", {}),
        ("http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/"
         "access-configs/0/external-ip", {"Metadata-Flavor": "Google"}),
    )
    public_sources = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")

    with httpx.Client(timeout=timeout) as client:
        for url, headers in metadata_sources:
            try:
                response = client.get(url, headers=headers)
                if response.status_code == 200 and _looks_like_ipv4(response.text.strip()):
                    return response.text.strip()
            except httpx.HTTPError:
                continue
        for url in public_sources:
            try:
                response = client.get(url)
                if response.status_code == 200 and _looks_like_ipv4(response.text.strip()):
                    return response.text.strip()
            except httpx.HTTPError:
                continue
    return None


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
