"""Health checks — the guide's §23 verification matrix and §21 troubleshooting, automated.

Each check answers one question with a pass/fail and, when it fails, the specific remedy.
A failing check that just says "broken" costs an hour; one that names the fix costs a minute.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from types import SimpleNamespace

import httpx
from sqlalchemy import select

from ..config import Config
from ..system import dockerx, firewall, sysctl
from ..system import wireguard as wg
from ..system.shell import has

log = logging.getLogger("edgekit.health")


class Level(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class Check:
    key: str
    title: str
    level: Level
    detail: str = ""
    remedy: str = ""

    @property
    def ok(self) -> bool:
        return self.level in (Level.OK, Level.SKIP)


@dataclass
class HealthReport:
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.level is not Level.FAIL for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.level is Level.FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.level is Level.WARN]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "failures": len(self.failures),
            "warnings": len(self.warnings),
            "checks": [
                {
                    "key": c.key,
                    "title": c.title,
                    "level": c.level.value,
                    "detail": c.detail,
                    "remedy": c.remedy,
                }
                for c in self.checks
            ],
        }


# Reachability probes should fail fast: a hung peer must not stall the whole report.
PROBE_TIMEOUT = 4.0
PUBLIC_TIMEOUT = 6.0


def _local_checks(config: Config, peers: list) -> list[Check]:
    """Synchronous host checks (wg, sysctl, iptables, docker). Run in a worker thread."""
    checks: list[Check] = []
    checks.extend(_check_wireguard(config, peers))
    checks.append(_check_forwarding())
    checks.append(_check_firewall(config))
    checks.extend(_check_docker(config))
    return checks


async def run_all(config: Config, peers: list | None = None) -> HealthReport:
    peer_list = list(peers or [])
    # Snapshot ORM attributes on this thread before the worker touches them.
    peer_views = [
        SimpleNamespace(
            id=p.id,
            name=p.name,
            address=p.address,
            public_key=p.public_key,
            enabled=p.enabled,
        )
        for p in peer_list
    ]
    local, tls, npm, public = await asyncio.gather(
        asyncio.to_thread(_local_checks, config, peer_views),
        _check_certificate(config),
        _check_npm(config),
        _check_public(config),
    )
    # Ordered the way the request travels: this host, then its certificate and nginx, then
    # what nginx can reach, then the public path. A failure reads as the first layer that
    # broke rather than as a list to correlate by hand.
    return HealthReport([*local, *tls, *npm, *public])


# ---------------------------------------------------------------------- WireGuard


def _check_wireguard(config: Config, peers: list) -> list[Check]:
    interface = config.wireguard.interface
    checks: list[Check] = []

    if not has("wg"):
        return [
            Check(
                "wg_installed",
                "WireGuard installed",
                Level.FAIL,
                "the `wg` binary is not on PATH",
                "Run `edgekit provision` or `apt install wireguard`.",
            )
        ]

    if not wg.interface_exists(interface):
        checks.append(
            Check(
                "wg_interface",
                f"Interface {interface} up",
                Level.FAIL,
                f"{interface} does not exist",
                f"Run `wg-quick up {interface}`, then check "
                f"`systemctl status wg-quick@{interface}`.",
            )
        )
        return checks

    checks.append(
        Check("wg_interface", f"Interface {interface} up", Level.OK, config.wireguard.hub_address)
    )

    live = {p.public_key: p for p in wg.status(interface)}
    for peer in peers:
        if not peer.enabled:
            checks.append(
                Check(f"peer_{peer.id}", f"Peer {peer.name}", Level.SKIP, "disabled")
            )
            continue

        state = live.get(peer.public_key)
        if state is None:
            checks.append(
                Check(
                    f"peer_{peer.id}",
                    f"Peer {peer.name}",
                    Level.FAIL,
                    "not loaded into the running interface",
                    "Run `edgekit peer sync` to regenerate and apply wg0.conf.",
                )
            )
        elif not state.connected:
            checks.append(
                Check(
                    f"peer_{peer.id}",
                    f"Peer {peer.name} ({peer.address})",
                    Level.WARN,
                    "no recent handshake",
                    f"On the peer: check `Endpoint = {config.server.public_ip}:"
                    f"{config.wireguard.listen_port}` and that UDP "
                    f"{config.wireguard.listen_port} is open in the cloud firewall "
                    "(AWS security group, etc.) — that rule lives outside this host.",
                )
            )
        else:
            checks.append(
                Check(
                    f"peer_{peer.id}",
                    f"Peer {peer.name} ({peer.address})",
                    Level.OK,
                    f"handshake ok, rx {_human(state.rx_bytes)} / tx {_human(state.tx_bytes)}",
                )
            )
    return checks


# ---------------------------------------------------------------------- routing


def _check_forwarding() -> Check:
    results = sysctl.verify()
    if results.get("net.ipv4.ip_forward"):
        return Check("ip_forward", "IP forwarding enabled", Level.OK, "net.ipv4.ip_forward = 1")
    return Check(
        "ip_forward",
        "IP forwarding enabled",
        Level.FAIL,
        "net.ipv4.ip_forward is 0",
        "Run `edgekit provision`, or `sysctl -w net.ipv4.ip_forward=1`. Without this, "
        "Nginx Proxy Manager cannot reach any peer.",
    )


def _check_firewall(config: Config) -> Check:
    if not has("iptables"):
        return Check("fw_rules", "Docker to WireGuard rules", Level.SKIP, "iptables not present")

    # NPM lives on its Compose project network, so the rules have to name that bridge.
    bridge = firewall.detect_proxy_bridge(config)
    present = firewall.rules_present(
        docker_subnet=bridge.subnet,
        wg_subnet=config.wireguard.subnet,
        wg_if=config.wireguard.interface,
        docker_if=bridge.interface,
    )
    if present:
        return Check(
            "fw_rules",
            "Docker to WireGuard rules",
            Level.OK,
            f"{bridge.interface} {bridge.subnet} -> {config.wireguard.subnet}",
        )
    return Check(
        "fw_rules",
        "Docker to WireGuard rules",
        Level.FAIL,
        f"forwarding or NAT rules are missing for {bridge.interface} ({bridge.subnet})",
        "Run `systemctl start edgekit-firewall` (or `edgekit provision`). The rules must "
        f"name the network {config.npm.container_name} is on ({bridge.network}), not the "
        "default bridge — check with `docker inspect "
        f"{config.npm.container_name} --format '{{{{json .NetworkSettings.Networks}}}}'`.",
    )


# ---------------------------------------------------------------------- Docker / NPM


def _check_docker(config: Config) -> list[Check]:
    if not has("docker"):
        return [
            Check(
                "docker",
                "Docker running",
                Level.FAIL,
                "docker is not installed",
                "Run `edgekit provision`.",
            )
        ]
    if not dockerx.daemon_running():
        return [
            Check(
                "docker",
                "Docker running",
                Level.FAIL,
                "the Docker daemon is not responding",
                "Run `systemctl start docker` and check `journalctl -u docker`.",
            )
        ]

    checks = [Check("docker", "Docker running", Level.OK)]
    state = dockerx.container_state(config.npm.container_name)
    if state.get("running"):
        checks.append(
            Check(
                "npm_container",
                "Nginx Proxy Manager container",
                Level.OK,
                f"{state.get('status')} ({state.get('image')})",
            )
        )
    else:
        checks.append(
            Check(
                "npm_container",
                "Nginx Proxy Manager container",
                Level.FAIL,
                f"container is {state.get('status')}",
                f"Check `docker logs {config.npm.container_name} --tail 100`, then "
                "`cd /opt/nginx-proxy-manager && docker compose up -d`.",
            )
        )
    return checks


async def _check_npm(config: Config) -> list[Check]:
    state = await asyncio.to_thread(dockerx.container_state, config.npm.container_name)
    if not state.get("running"):
        return []

    # Guide §17: the check that actually matters is from *inside* the container.
    from ..db import session_scope
    from ..models import ProxyHost

    with session_scope() as session:
        targets = [
            (h.domain, h.forward_host, h.forward_port, h.scheme)
            for h in session.scalars(select(ProxyHost))
        ]
    if not targets:
        return []

    reach, tls = await asyncio.gather(
        asyncio.gather(*(_reach_from_container(config, t) for t in targets)),
        _probe_all_local(config, [t[0] for t in targets]),
    )
    return [*reach, *tls]


async def _reach_from_container(config: Config, target: tuple) -> Check:
    domain, host, port, scheme = target
    result = await asyncio.to_thread(
        dockerx.curl_from_container,
        config.npm.container_name,
        f"{scheme}://{host}:{port}",
        int(PROBE_TIMEOUT),
    )
    code = (result.stdout or "").strip()
    if code and code != "000":
        level = Level.OK if code[0] in "23" else Level.WARN
        return Check(
            f"npm_reach_{domain}",
            f"NPM can reach {host}:{port}",
            level,
            f"HTTP {code}",
            "" if level is Level.OK else
            f"The tunnel works but the service returned {code}. Check the service "
            f"on the peer.",
        )
    if host == config.panel.bind and port == config.panel.port:
        bridges = firewall.container_bridges(config.npm.container_name)
        subnet = (
            bridges[0].subnet
            if bridges
            else (config.server.docker_bridge_subnet or "172.17.0.0/16")
        )
        remedy = (
            f"The panel is on this host. ufw default-deny drops Docker INPUT to "
            f"{host}:{port}. Allow the network {config.npm.container_name} is really on "
            f"— Compose gives it one of its own, not the default bridge: "
            f"`ufw allow from {subnet} to {host} port {port} proto tcp` "
            f"(or `edgekit firewall setup`)."
        )
    else:
        remedy = (
            "Verify the service is listening on the peer, then check IP forwarding "
            "and the Docker-to-WireGuard rules above."
        )
    return Check(
        f"npm_reach_{domain}",
        f"NPM can reach {host}:{port}",
        Level.FAIL,
        "no response from inside the container",
        remedy,
    )


def _https_sni(address: str, domain: str, port: int) -> int:
    """TLS to ``address`` using ``domain`` as SNI. A Host header alone is not enough."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, port), timeout=PROBE_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            tls.settimeout(PROBE_TIMEOUT)
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
            )
            first = tls.recv(1024)
    if not first:
        raise OSError("TLS connected but origin returned no HTTP response")
    line = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise OSError(f"bad HTTP status line: {line[:80]}")
    return int(parts[1])


async def _probe_all_local(config: Config, domains: list[str]) -> list[Check]:
    """Two of the three TLS layers: nginx itself, then the same nginx over the public IP.

    Separating them is what turns "525" into an answer. Local TLS good and origin TLS bad
    means nothing is wrong with the certificate — port 443 is not reaching this host.
    """
    port = config.npm.https_port
    checks = list(await asyncio.gather(*(_probe_local_proxy(d, port) for d in domains)))
    public_ip = (config.server.public_ip or "").strip()
    if public_ip:
        checks.extend(
            await asyncio.gather(*(_probe_origin(public_ip, d, port) for d in domains))
        )
    return checks


async def _probe_local_proxy(domain: str, port: int) -> Check:
    try:
        # SNI must be the vhost name. Connecting to 127.0.0.1 with only a Host header
        # makes OpenResty return TLSV1_UNRECOGNIZED_NAME even when the origin cert is fine.
        status = await asyncio.to_thread(_https_sni, "127.0.0.1", domain, port)
    except OSError as exc:
        return Check(
            f"local_tls_{domain}",
            f"Local TLS for {domain}",
            Level.FAIL,
            str(exc)[:200],
            "This is what produces a Cloudflare 525. Confirm an origin certificate is "
            "installed in NPM and attached to this host: `edgekit cert status`.",
        )
    return Check(
        f"local_tls_{domain}",
        f"Local TLS for {domain}",
        Level.OK if status < 500 else Level.WARN,
        f"HTTP {status}",
    )


async def _probe_origin(public_ip: str, domain: str, port: int) -> Check:
    """The hop Cloudflare makes: TLS to the public IP with this hostname as SNI."""
    try:
        status = await asyncio.to_thread(_https_sni, public_ip, domain, port)
    except OSError as exc:
        return Check(
            f"origin_tls_{domain}",
            f"Origin TLS for {domain} on {public_ip}",
            Level.WARN,
            str(exc)[:200],
            "Nginx answered on 127.0.0.1 but not on the public address. That is a network "
            f"path problem, not a certificate one: check that TCP {port} is open in the "
            "cloud firewall (security group, provider firewall) and reachable from "
            "outside. Some hosts also block hairpin connections to their own public IP, "
            "which makes this check fail even when Cloudflare succeeds.",
        )
    return Check(
        f"origin_tls_{domain}",
        f"Origin TLS for {domain} on {public_ip}",
        Level.OK if status < 500 else Level.WARN,
        f"HTTP {status}",
    )


# ---------------------------------------------------------------------- certificate

#: Cloudflare sends no expiry notice for Origin CA certificates, so this is the only warning
#: the operator gets. Escalating thresholds rather than one, so a missed week still nags.
EXPIRY_WARN_DAYS = 30
EXPIRY_URGENT_DAYS = 7


async def _check_certificate(config: Config) -> list[Check]:
    from ..db import session_scope
    from ..models import ProxyHost
    from .certificates import CertificateError, inspect_certificate
    from .hosts import SETTING_CERT_EXPIRY, SETTING_CERT_ID, get_setting

    with session_scope() as session:
        cert_id = get_setting(session, SETTING_CERT_ID)
        expiry_raw = get_setting(session, SETTING_CERT_EXPIRY)
        domains = [h.domain for h in session.scalars(select(ProxyHost))]

    if not cert_id:
        return [
            Check(
                "origin_cert",
                "Origin certificate installed",
                Level.FAIL,
                "no origin certificate is recorded",
                "Cloudflare answers 525 for every hostname while it is set to Full (strict) "
                "and the origin has no certificate. Install one with "
                "`edgekit cert install --cert FILE --key FILE`.",
            )
        ]

    checks = [
        Check("origin_cert", "Origin certificate installed", Level.OK, f"NPM id {cert_id}")
    ]
    checks.extend(_expiry_checks(expiry_raw))

    # Coverage can only be judged against the certificate itself, which is stored only when
    # the operator supplied it. The Cloudflare-issued path always covers *.zone by design.
    if config.tls.certificate and domains:
        try:
            info = inspect_certificate(config.tls.certificate)
        except CertificateError as exc:
            checks.append(
                Check(
                    "cert_readable",
                    "Origin certificate readable",
                    Level.FAIL,
                    str(exc)[:200],
                    "Reinstall it with `edgekit cert install --cert FILE --key FILE`.",
                )
            )
        else:
            uncovered = [d for d in domains if not info.covers(d)]
            zone = config.cloudflare.zone_name or "yourzone"
            remedy = (
                "Cloudflare answers 526 for a hostname the origin certificate does not "
                f"name: the handshake succeeds and the certificate is then refused. Issue "
                f"one covering *.{zone}, install it with `edgekit cert install`, then run "
                "`edgekit host resync`."
            )
            checks.append(
                Check(
                    "cert_coverage",
                    "Certificate covers every host",
                    Level.FAIL if uncovered else Level.OK,
                    ", ".join(uncovered) if uncovered else ", ".join(info.hostnames),
                    remedy if uncovered else "",
                )
            )

    checks.append(await _check_nginx_config(config))
    return checks


def _expiry_checks(expiry_raw: str) -> list[Check]:
    if not expiry_raw:
        return []
    try:
        expires = dt.datetime.fromisoformat(expiry_raw)
    except ValueError:
        return []
    days = (expires - dt.datetime.now(dt.timezone.utc)).days
    if days < 0:
        level, remedy = Level.FAIL, "Issue a new origin certificate and install it."
    elif days <= EXPIRY_URGENT_DAYS:
        level, remedy = Level.FAIL, "Replace it now — Full (strict) fails the moment it lapses."
    elif days <= EXPIRY_WARN_DAYS:
        level, remedy = Level.WARN, "Plan the replacement; Cloudflare sends no expiry notice."
    else:
        level, remedy = Level.OK, ""
    detail = f"expired {-days} days ago" if days < 0 else f"{days} days remaining"
    return [
        Check(
            "cert_expiry",
            "Origin certificate validity",
            level,
            f"{detail} ({expires.date()})",
            remedy,
        )
    ]


async def _check_nginx_config(config: Config) -> Check:
    ok, output = await asyncio.to_thread(dockerx.nginx_config_test, config.npm.container_name)
    if ok is None:
        return Check("nginx_config", "Nginx configuration valid", Level.SKIP, output[:200])
    if ok:
        return Check("nginx_config", "Nginx configuration valid", Level.OK, "nginx -t passed")
    return Check(
        "nginx_config",
        "Nginx configuration valid",
        Level.FAIL,
        output[-300:],
        "Nginx will not load this configuration, so TLS fails and Cloudflare reports 525. "
        "A vhost pointing at a certificate that is no longer on disk is the usual cause: "
        "run `edgekit cert install` again, then `edgekit host resync`.",
    )


# ---------------------------------------------------------------------- public


async def _check_public(config: Config) -> list[Check]:
    from ..db import session_scope
    from ..models import ProxyHost

    with session_scope() as session:
        domains = [h.domain for h in session.scalars(select(ProxyHost))]
    if not domains:
        return []

    timeout = httpx.Timeout(PUBLIC_TIMEOUT, connect=2.0)

    async def probe(client: httpx.AsyncClient, domain: str) -> Check:
        try:
            response = await client.head(f"https://{domain}")
        except httpx.HTTPError as exc:
            return Check(
                f"public_{domain}",
                f"Public https://{domain}",
                Level.WARN,
                str(exc)[:200],
                "Check the Cloudflare DNS record exists and is proxied, and that DNS has "
                "propagated.",
            )

        if response.status_code == 525:
            return Check(
                f"public_{domain}",
                f"Public https://{domain}",
                Level.FAIL,
                "HTTP 525 — the Cloudflare-to-origin TLS handshake failed",
                "Cloudflare reached port 443 but could not complete TLS. It never saw a "
                "usable certificate, so this is a handshake problem, not a trust one: a "
                "vhost nginx refused to load, an SNI with no matching proxy host, or 443 "
                "answered by something else. Check the nginx and local TLS results above.",
            )
        if response.status_code == 526:
            return Check(
                f"public_{domain}",
                f"Public https://{domain}",
                Level.FAIL,
                "HTTP 526 — Cloudflare rejected this origin's certificate",
                "The handshake worked, so nginx and the vhost are fine. Cloudflare would "
                "not accept the certificate itself: expired, not covering this hostname, "
                "or not issued by a CA it trusts. A Cloudflare Origin CA certificate "
                "covering *." + (config.cloudflare.zone_name or "yourzone") + " is what "
                "Full (strict) expects — check `edgekit cert status`.",
            )
        level = Level.OK if response.status_code < 500 else Level.WARN
        return Check(
            f"public_{domain}",
            f"Public https://{domain}",
            level,
            f"HTTP {response.status_code} via {response.headers.get('server', 'unknown')}",
        )

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return list(await asyncio.gather(*(probe(client, d) for d in domains)))


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PiB"


def cloud_firewall_reminder(config: Config) -> Check:
    """Not something we can verify from inside the host — surfaced as a standing reminder."""
    opened = ", ".join(
        f"{r.protocol.upper()} {r.port}"
        for r in firewall.cloud_firewall_ports(config)
        if r.action == "open"
    )
    closed = ", ".join(
        f"{r.protocol.upper()} {r.port}"
        for r in firewall.cloud_firewall_ports(config)
        if r.action == "closed"
    )
    return Check(
        "cloud_firewall",
        "Cloud firewall (manual)",
        Level.WARN,
        "edgekit cannot see your cloud provider's firewall",
        f"Open inbound {opened}. Keep closed: {closed}.",
    )
