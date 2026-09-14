"""Health checks — the guide's §23 verification matrix and §21 troubleshooting, automated.

Each check answers one question with a pass/fail and, when it fails, the specific remedy.
A failing check that just says "broken" costs an hour; one that names the fix costs a minute.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from enum import Enum
from types import SimpleNamespace

import certifi
import httpx
from cryptography import x509
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
    local, cloudflare, tls, npm, public = await asyncio.gather(
        asyncio.to_thread(_local_checks, config, peer_views),
        _check_cloudflare(config),
        _check_certificate(config),
        _check_npm(config),
        _check_public(config),
    )
    # Ordered the way the request travels: this host, then where DNS sends visitors, then the
    # certificate and nginx, then what nginx can reach, then the public path. A failure reads
    # as the first layer that broke rather than as a list to correlate by hand.
    return HealthReport([*local, *cloudflare, *tls, *npm, *public])


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


def _https_sni(address: str, domain: str, port: int) -> int | None:
    """TLS to ``address`` using ``domain`` as SNI. A Host header alone is not enough.

    Returns the HTTP status, or None when the handshake completed but no response arrived in
    time. That is nginx waiting on a slow or unreachable upstream — not a TLS failure, and it
    must not be reported as one.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, port), timeout=PROBE_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            return _read_status(tls, domain, PROBE_TIMEOUT)


def _read_status(tls: ssl.SSLSocket, domain: str, timeout: float) -> int | None:
    """Send a request on an established TLS connection and parse the status line."""
    tls.settimeout(timeout)
    tls.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
    try:
        first = tls.recv(1024)
    except TimeoutError:
        return None
    if not first:
        raise OSError("TLS connected but origin returned no HTTP response")
    line = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise OSError(f"bad HTTP status line: {line[:80]}")
    return int(parts[1])


def _no_response(key: str, title: str) -> Check:
    return Check(
        key,
        title,
        Level.WARN,
        f"TLS handshake ok; no HTTP response within {PROBE_TIMEOUT:.0f}s",
        "Not a certificate problem: nginx accepted the connection and is waiting on the "
        "service behind this host. Check its `NPM can reach` result — an offline peer looks "
        "exactly like this.",
    )


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
            "A handshake failing here is what Cloudflare reports as 525, and what a browser "
            "reports as a TLS error with DNS only. Confirm a certificate is installed in NPM "
            "and attached to this host: `edgekit cert status`.",
        )
    if status is None:
        return _no_response(f"local_tls_{domain}", f"Local TLS for {domain}")
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
    if status is None:
        return _no_response(f"origin_tls_{domain}", f"Origin TLS for {domain} on {public_ip}")
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

    proxied = config.dns_proxied
    label = "Origin certificate" if proxied else "Let's Encrypt certificate"
    if not cert_id:
        return [
            Check(
                "origin_cert",
                f"{label} installed",
                Level.FAIL,
                "no certificate is recorded",
                "Cloudflare answers 525 for every hostname while it is set to Full (strict) "
                "and the origin has no certificate. Install one with "
                "`edgekit cert install --cert FILE --key FILE`."
                if proxied
                else "Direct mode serves browsers from this server, so without a certificate "
                "every HTTPS request fails. `edgekit provision` issues one.",
            )
        ]

    checks = [Check("origin_cert", f"{label} installed", Level.OK, f"NPM id {cert_id}")]
    if not proxied:
        # NPM renews Let's Encrypt certificates itself; the expiry recorded at issuance goes
        # stale after the first renewal, so ask NPM for the current one.
        expiry_raw = await _live_expiry(config, cert_id) or expiry_raw
    checks.extend(_expiry_checks(expiry_raw, config.tls.mode))

    # Coverage can only be judged against the certificate itself, which is stored only when
    # the operator supplied it. The Cloudflare-issued path always covers *.zone by design,
    # and so does the Let's Encrypt one direct mode uses.
    if proxied and config.tls.certificate and domains:
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


async def _live_expiry(config: Config, cert_id: str) -> str:
    """The expiry NPM currently reports for ``cert_id``, or "" when NPM cannot be asked."""
    from .certificates import parse_npm_timestamp
    from .npm import NPMClient, NPMError

    npm = config.npm
    try:
        async with NPMClient(
            npm.api_base, npm.admin_email, npm.admin_password, timeout=PROBE_TIMEOUT
        ) as client:
            for certificate in await client.list_certificates():
                if str(certificate.get("id")) == str(cert_id):
                    when = parse_npm_timestamp(certificate.get("expires_on"))
                    return when.isoformat() if when else ""
    except (NPMError, httpx.HTTPError):
        pass
    return ""


def _expiry_checks(expiry_raw: str, mode: str = "proxied") -> list[Check]:
    if not expiry_raw:
        return []
    try:
        expires = dt.datetime.fromisoformat(expiry_raw)
    except ValueError:
        return []
    days = (expires - dt.datetime.now(dt.timezone.utc)).days
    # NPM renews a Let's Encrypt certificate with 30 days left, so reaching the warning window
    # at all means renewal is failing; an Origin certificate is only ever replaced by hand.
    renewal = (
        "NPM should have renewed this 30 days before expiry. Look for certbot errors in "
        "`docker logs nginx-proxy-manager --tail 200`, then run `edgekit provision`."
    )
    if days < 0:
        level = Level.FAIL
        remedy = (
            "Issue a new one: `edgekit provision`."
            if mode == "direct"
            else "Issue a new origin certificate and install it."
        )
    elif days <= EXPIRY_URGENT_DAYS:
        level = Level.FAIL
        remedy = (
            renewal if mode == "direct"
            else "Replace it now — Full (strict) fails the moment it lapses."
        )
    elif days <= EXPIRY_WARN_DAYS:
        level = Level.WARN
        remedy = (
            renewal if mode == "direct"
            else "Plan the replacement; Cloudflare sends no expiry notice."
        )
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


#: Part of the issuer of every Cloudflare Origin CA certificate. Nothing but Cloudflare's
#: proxy trusts that CA, so a browser that is shown one has bypassed the proxy.
ORIGIN_CA_ISSUER = "cloudflare origin"


@dataclass
class PublicProbe:
    """What a browser gets for one hostname: where DNS sends it and the certificate it sees."""

    domain: str
    addresses: list[str] = field(default_factory=list)
    #: True or False once a certificate was presented; None if TLS never got that far.
    trusted: bool | None = None
    issuer: str = ""
    status: int | None = None
    error: str = ""

    @property
    def origin_certificate(self) -> bool:
        return ORIGIN_CA_ISSUER in self.issuer.lower()


def _peer_issuer(tls: ssl.SSLSocket) -> str:
    der = tls.getpeercert(binary_form=True)
    if not der:
        return ""
    try:
        return x509.load_der_x509_certificate(der).issuer.rfc4514_string()
    except ValueError:
        return ""


def _served_issuer(domain: str, port: int, timeout: float) -> str:
    """The issuer of whatever certificate ``domain`` presents, trusted or not."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                return _peer_issuer(tls)
    except OSError:
        return ""


def _issuer_name(issuer: str) -> str:
    """The O= part of an RFC 4514 issuer — the name people recognise a CA by."""
    for part in re.split(r"(?<!\\),", issuer):
        if part.startswith("O="):
            return part[2:].replace("\\,", ",")
    return issuer or "an unknown issuer"


def probe_public_https(
    domain: str, port: int = 443, timeout: float = PUBLIC_TIMEOUT
) -> PublicProbe:
    """Connect the way a browser does: public DNS, and a certificate that must verify."""
    probe = PublicProbe(domain)
    try:
        infos = socket.getaddrinfo(domain, port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        probe.error = f"does not resolve: {exc}"
        return probe
    probe.addresses = sorted({info[4][0] for info in infos})

    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                probe.trusted = True
                probe.issuer = _peer_issuer(tls)
                probe.status = _read_status(tls, domain, timeout)
    except ssl.SSLCertVerificationError as exc:
        probe.trusted = False
        probe.error = exc.verify_message or str(exc)
        probe.issuer = _served_issuer(domain, port, timeout)
    except OSError as exc:
        probe.error = str(exc)[:200]
    return probe


def assess_public(probe: PublicProbe, config: Config) -> tuple[Check, bool]:
    """Judge what a browser gets for one hostname against the configured TLS mode.

    Returns the check and whether asking again shortly could change the answer — true only
    for states a DNS change that was just applied explains, since resolvers keep the old
    answer for up to its TTL (five minutes for an automatic one).
    """
    key, title = f"public_{probe.domain}", f"Public https://{probe.domain}"
    proxied = config.dns_proxied
    public_ip = (config.server.public_ip or "").strip()
    points_here = bool(public_ip) and public_ip in probe.addresses
    to_direct = (
        "If Cloudflare cannot complete TLS with this server, switch modes instead: "
        "`edgekit ssl mode direct` serves a Let's Encrypt certificate that works with DNS only."
    )

    def check(level: Level, detail: str, remedy: str = "") -> Check:
        return Check(key, title, level, detail, remedy)

    if probe.trusted is None:
        if not probe.addresses:
            return check(
                Level.FAIL,
                probe.error or "does not resolve",
                "No A record answers for this name. `edgekit provision` publishes the zone's "
                "@ and * records.",
            ), True
        return check(
            Level.WARN,
            f"could not connect from this server: {probe.error}",
            "edgekit could not see what a browser sees. Check from another network: "
            f"`curl -I https://{probe.domain}`.",
        ), False

    if probe.trusted is False:
        if probe.origin_certificate and proxied:
            return check(
                Level.FAIL,
                "DNS only: browsers reach this server directly and are shown the Cloudflare "
                "Origin certificate, which only Cloudflare's proxy trusts",
                "Set the record to Proxied (orange cloud) — `edgekit provision` does it with "
                f"the stored Cloudflare token. {to_direct}",
            ), points_here
        if probe.origin_certificate:
            return check(
                Level.FAIL,
                "browsers are shown the Cloudflare Origin certificate, which only "
                "Cloudflare's proxy trusts",
                "Direct mode needs the Let's Encrypt certificate on every proxy host: run "
                "`edgekit provision`.",
            ), False
        return check(
            Level.FAIL,
            f"untrusted certificate from {_issuer_name(probe.issuer)}: {probe.error}",
            "Run `edgekit provision` to install the certificate this mode expects.",
        ), False

    issuer = _issuer_name(probe.issuer)
    if proxied and points_here:
        return check(
            Level.WARN,
            f"certificate from {issuer} is trusted, but DNS points straight at this server "
            "instead of through Cloudflare",
            "Proxied mode expects the record Proxied: `edgekit provision` sets it. Resolvers "
            "can keep the old answer for five minutes.",
        ), True
    if not proxied and public_ip and not points_here:
        return check(
            Level.WARN,
            f"still answered through Cloudflare ({', '.join(probe.addresses)})",
            "Direct mode expects DNS only: `edgekit provision` sets it. Resolvers can keep "
            "the old answer for five minutes.",
        ), True
    if probe.status == 525:
        return check(
            Level.FAIL,
            "HTTP 525 — Cloudflare could not complete TLS with this server",
            "When local TLS passes (`edgekit doctor`) the certificate is not the cause: "
            f"Cloudflare's own connection to {public_ip or 'the origin'}:443 is refused or "
            f"reset on the way. {to_direct}",
        ), True
    if probe.status == 526:
        return check(
            Level.FAIL,
            "HTTP 526 — Cloudflare rejected this origin's certificate",
            "The handshake worked, so nginx and the vhost are fine; Cloudflare would not "
            "accept the certificate itself: expired, not covering this hostname, or not from "
            "a CA it trusts. `edgekit provision` reinstalls the Origin certificate.",
        ), False
    if probe.status is None:
        return check(
            Level.WARN,
            f"certificate from {issuer} is trusted; no HTTP response within "
            f"{PUBLIC_TIMEOUT:.0f}s",
            "TLS is fine. The service behind this host is slow or down — see its `NPM can "
            "reach` result.",
        ), False
    if probe.status >= 500:
        return check(
            Level.WARN,
            f"certificate from {issuer} is trusted; HTTP {probe.status}",
            "TLS is fine. The service behind this host answered with an error — see its "
            "`NPM can reach` result.",
        ), False
    return check(Level.OK, f"HTTP {probe.status}, certificate from {issuer}"), False


async def _check_public(config: Config) -> list[Check]:
    from ..db import session_scope
    from ..models import ProxyHost

    with session_scope() as session:
        domains = [h.domain for h in session.scalars(select(ProxyHost))]
    if not domains:
        return []

    probes = await asyncio.gather(
        *(asyncio.to_thread(probe_public_https, domain) for domain in domains)
    )
    return [assess_public(probe, config)[0] for probe in probes]


# ---------------------------------------------------------------------- Cloudflare


async def _check_cloudflare(config: Config) -> list[Check]:
    """Whether DNS and the zone's SSL mode match the certificate this edge serves.

    This is the authoritative version of what the public probe infers: a record with the
    wrong proxy status is the difference between a trusted and an untrusted certificate.
    """
    from .cloudflare import CloudflareClient, CloudflareError

    cf = config.cloudflare
    if not (cf.enabled and cf.api_token and cf.zone_id):
        if not cf.zone_name:
            return []
        return [
            Check(
                "cf_api",
                "Cloudflare API",
                Level.FAIL,
                "no Cloudflare API token is stored",
                "edgekit keeps DNS proxy status and the SSL mode in step with the certificate "
                "it installs, which needs a token: "
                f"`edgekit cloudflare token --zone {cf.zone_name}`.",
            )
        ]

    proxied = config.dns_proxied
    public_ip = (config.server.public_ip or "").strip()
    try:
        async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
            records = [r for r in await client.list_a_records(cf.zone_id)
                       if r.get("content") == public_ip]
            ssl_mode = await client.get_ssl_mode(cf.zone_id) if proxied else ""
    except (CloudflareError, httpx.HTTPError) as exc:
        return [
            Check(
                "cf_api",
                "Cloudflare API",
                Level.WARN,
                str(exc)[:200],
                "Check the stored token with `edgekit cloudflare verify`.",
            )
        ]

    wrong = sorted(
        r.get("name", "?")
        for r in records
        if bool(r.get("proxied")) != proxied and not (proxied and r.get("proxiable") is False)
    )
    wanted = "Proxied" if proxied else "DNS only"
    checks = [
        Check(
            "cf_dns_proxy",
            f"DNS records {wanted} ({config.tls.mode} mode)",
            Level.FAIL if wrong else Level.OK,
            ", ".join(wrong) if wrong else f"{len(records)} record(s) pointing at {public_ip}",
            (
                "These resolve straight to this server, so browsers are shown the Origin "
                "certificate only Cloudflare trusts. `edgekit provision` switches them to "
                "Proxied."
                if proxied
                else "These go through Cloudflare, which direct mode does not use. "
                "`edgekit provision` switches them to DNS only."
            )
            if wrong
            else "",
        )
    ]
    if proxied:
        strict = ssl_mode == "strict"
        checks.append(
            Check(
                "cf_ssl_mode",
                "Cloudflare SSL mode Full (strict)",
                Level.OK if strict else Level.FAIL,
                ssl_mode or "unknown",
                ""
                if strict
                else "Full (strict) is the mode that works with an Origin certificate: "
                "Flexible loops on NPM's HTTPS redirect and Full verifies nothing. "
                "`edgekit provision` sets it.",
            )
        )
    return checks


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
