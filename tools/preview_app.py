"""A runnable preview of the edgekit panel.

The panel normally needs a provisioned server: root, a live WireGuard interface, and a
Docker daemon running Nginx Proxy Manager. None of that exists on a laptop, so this module
builds the same FastAPI app against a throwaway state directory and replaces the handful of
functions that shell out with fixtures.

Nothing here is imported by the package itself — ``edgekit`` is untouched, and the stubs are
installed on module attributes at import time, exactly as the test-suite fixtures do it.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# edgekit.paths reads EDGEKIT_ROOT at import time, so it has to be set before the first
# edgekit import — everything the preview writes then lands under .preview/, never in /etc.
PREVIEW_ROOT = Path(
    os.environ.setdefault("EDGEKIT_ROOT", str(REPO_ROOT / ".preview" / "root"))
)
PREVIEW_ROOT.mkdir(parents=True, exist_ok=True)

# Works from a plain checkout as well as an installed venv.
sys.path.insert(0, str(REPO_ROOT / "src"))

from fastapi import APIRouter, Request  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402

from edgekit import db as db_module  # noqa: E402
from edgekit.config import Config  # noqa: E402
from edgekit.models import AuditLog, Base, Peer, ProxyHost, Setting, User  # noqa: E402
from edgekit.security import hash_password  # noqa: E402
from edgekit.services import health  # noqa: E402
from edgekit.services.hosts import (  # noqa: E402
    SETTING_CERT_EXPIRY,
    SETTING_CERT_ID,
    SETTING_CERT_NAME,
)
from edgekit.system import dockerx  # noqa: E402
from edgekit.system import wireguard as wg  # noqa: E402
from edgekit.web import deps  # noqa: E402
from edgekit.web.app import create_app  # noqa: E402

SCENARIOS = ("populated", "healthy", "empty", "degraded")
PASSWORD = "preview-password"
ZONE = "blockey.ir"

#: Mutated by :func:`seed` so the stubs below answer consistently with the database.
STATE: dict = {"scenario": "populated"}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ago(**kwargs) -> dt.datetime:
    return now() - dt.timedelta(**kwargs)


# --------------------------------------------------------------------------- config


def build_config() -> Config:
    config = Config()
    config.server.public_ip = "52.56.216.78"
    config.server.hostname = "edge-lon-1"
    config.server.docker_bridge_subnet = "172.19.0.0/16"
    config.server.ssh_user = "ubuntu"

    config.wireguard.subnet = "10.50.0.0/24"
    config.wireguard.listen_port = 51820
    config.wireguard.private_key = "8FqL2xVnT0cJhBpZ4dRwYsG1oTuI7eXzQwRjNkMaBc0="
    config.wireguard.public_key = "kR7dWq3ZtP0hMxJ9vLcB2nYs5EaG1oTuI8fXzQwRjNk="

    config.npm.container_name = "npm-app"
    config.npm.admin_email = f"admin@{ZONE}"
    config.npm.admin_password = "npm-preview-password"

    config.cloudflare.zone_name = ZONE
    config.cloudflare.enabled = False

    config.panel.bind = "127.0.0.1"
    config.panel.port = 8099
    # Stable so a restart does not invalidate the browser session you are previewing with.
    config.panel.session_secret = "preview-session-secret-not-used-anywhere-real"
    return config


CONFIG = build_config()


# ----------------------------------------------------------------------- fixtures

# (name, description, address, public key, extra routed CIDRs, enabled, handshake age s,
#  rx bytes, tx bytes, endpoint)
PEERS = [
    ("raspberry-pi", "Home Pi — retro + api", "10.50.0.2",
     "xTIB1cZ0mQ9pKfN3vRhLd8sWqA2yE7uJoP5gTnVbXkM=", "", True,
     14, 4_521_000_000, 851_000_000, "86.12.44.9:51820"),
    ("office-nas", "Synology — routes the office LAN", "10.50.0.3",
     "pL4mR8vX2nQ7bT0hJ6yW3cF9dK1sZ5aG8eU2iO4rY7M=", "192.168.1.0/24", True,
     48, 1_224_000_000, 333_000_000, "81.99.12.140:51820"),
    ("grafana-box", "Metrics VPS, Falkenstein", "10.50.0.4",
     "wN3jH7tB1kD9fS5xC2vP8mL4qR6yZ0aE3uI7oG1nT5Q=", "", True,
     62, 723_000_000, 2_201_000_000, "116.203.44.71:51820"),
    ("macbook-air", "Laptop, roaming", "10.50.0.5",
     "bV6cX9zM2pQ4wR7tY0uI3oA5sD8fG1hJ4kL7nB0mZ3E=", "", True,
     6 * 3600, 222_000_000, 49_000_000, None),
    ("backup-pi", "Cold spare", "10.50.0.6",
     "qW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xC2vB5nM8mQ1T=", "", False,
     None, 0, 0, None),
]

# (domain label, peer name or None, forward host, port, scheme, force_ssl, npm id)
HOSTS = [
    ("retro", "raspberry-pi", "10.50.0.2", 3001, "http", True, 4),
    ("api", "raspberry-pi", "10.50.0.2", 8080, "http", True, 5),
    ("nas", "office-nas", "10.50.0.3", 5001, "https", True, 6),
    ("metrics", "grafana-box", "10.50.0.4", 3000, "http", False, 7),
    ("edgekit", None, "10.50.0.1", 8088, "http", True, 3),
]

# (age kwargs, actor, action, target, detail, success)
AUDIT = [
    (dict(minutes=4), "admin", "host.create", f"metrics.{ZONE}",
     "forward 10.50.0.4:3000 via grafana-box, certificate attached", True),
    (dict(minutes=22), "admin", "peer.create", "grafana-box",
     "10.50.0.4/32, pre-shared key, wg syncconf applied", True),
    (dict(hours=1), "admin", "host.create", f"shop.{ZONE}",
     "NPM rejected the host: 502 from 10.50.0.5:4000", False),
    (dict(hours=3), "admin", "peer.rotate_keys", "macbook-air",
     "new keypair issued, client must reload its config", True),
    (dict(hours=5), "admin", "settings.wireguard", "wg0",
     "MTU 1420 -> 1380, interface restarted", True),
    (dict(days=1), "cli", "peer.delete", "old-laptop", "10.50.0.5 released, wg0 re-synced", True),
    (dict(days=1, hours=4), "admin", "host.update", f"nas.{ZONE}",
     "scheme http -> https, port 5000 -> 5001", True),
    (dict(days=2), "admin", "settings.npm", "npm-app",
     "admin email changed, API token re-issued", True),
    (dict(days=2, hours=6), "system", "provision.rerun", "hub",
     "14 steps completed, 0 changed", True),
    (dict(days=4), "admin", "peer.update", "office-nas", "routed 192.168.1.0/24 added", True),
    (dict(days=14), "system", "provision.run", "hub",
     "wireguard, sysctl, docker, npm-app, ufw, panel service", True),
]

FRESH_AUDIT = [
    (dict(minutes=4), "system", "provision.run", "hub",
     "wireguard, sysctl, docker, npm-app, ufw, panel service", True),
    (dict(minutes=5), "system", "settings.server", ZONE,
     "public IP 52.56.216.78, panel bound to 10.50.0.1:8088", True),
]


# --------------------------------------------------------------------------- seeding


def seed(scenario: str = "populated") -> None:
    """Rebuild the preview database from scratch for one scenario."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; expected one of {SCENARIOS}")
    STATE["scenario"] = scenario

    engine = db_module.get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    populated = scenario != "empty"

    with db_module.session_scope() as db:
        db.add(
            User(
                username="admin",
                password_hash=hash_password(PASSWORD),
                created_at=ago(days=14),
                last_login_at=ago(minutes=2),
                must_change_password=False,
            )
        )

        if not populated:
            for kwargs, actor, action, target, detail, ok in FRESH_AUDIT:
                db.add(AuditLog(created_at=ago(**kwargs), actor=actor, action=action,
                                target=target, detail=detail, success=ok))
            return

        peers: dict[str, Peer] = {}
        for name, desc, address, pubkey, extra, enabled, *_rest in PEERS:
            peer = Peer(
                name=name, description=desc, address=address, public_key=pubkey,
                private_key="8FqL2xVnT0cJhBpZ4dRwYsG1oTuI7eXzQwRjNkMaBc0=",
                preshared_key="mB4tZ1yQ8xKpD6wR0sHfNc2vB5nM8mQ1TeR7yU0iO3A=",
                extra_allowed_ips=extra, enabled=enabled, keepalive=25,
                created_at=ago(days=12),
            )
            db.add(peer)
            peers[name] = peer
        db.flush()

        for label, peer_name, fwd_host, port, scheme, force_ssl, npm_id in HOSTS:
            db.add(ProxyHost(
                domain=f"{label}.{ZONE}",
                peer_id=peers[peer_name].id if peer_name else None,
                forward_host=fwd_host, forward_port=port, scheme=scheme,
                force_ssl=force_ssl, http2=True, websockets=True, block_exploits=True,
                npm_host_id=npm_id, npm_certificate_id=2, created_at=ago(days=6),
            ))

        for kwargs, actor, action, target, detail, ok in AUDIT:
            db.add(AuditLog(created_at=ago(**kwargs), actor=actor, action=action,
                            target=target, detail=detail, success=ok))

        expiry = "2026-09-04T00:00:00Z" if scenario == "degraded" else "2040-08-14T00:00:00Z"
        db.add(Setting(key=SETTING_CERT_ID, value="2"))
        db.add(Setting(key=SETTING_CERT_NAME, value=f"Cloudflare Origin — {ZONE}"))
        db.add(Setting(key=SETTING_CERT_EXPIRY, value=expiry))


# ----------------------------------------------------------------------- stubs
#
# Each of these shells out to a binary that is not on a laptop. shell.run already degrades
# to "not found" rather than raising, so without stubs every page would render, but every
# status on it would be red — which is useless for looking at the design.


def _fake_status(interface: str) -> list:
    if STATE["scenario"] not in ("populated", "healthy"):
        return []          # a down interface reports no peers at all, same as `wg show`
    out = []
    for _name, _desc, address, pubkey, _extra, enabled, age, rx, tx, endpoint in PEERS:
        if not enabled or age is None:
            continue
        out.append(wg.PeerStatus(
            public_key=pubkey,
            endpoint=endpoint,
            allowed_ips=address + "/32",
            latest_handshake=int(now().timestamp()) - age,
            rx_bytes=rx,
            tx_bytes=tx,
        ))
    return out


def _fake_container_state(container: str) -> dict:
    if STATE["scenario"] == "degraded":
        return {"exists": True, "running": False, "status": "exited",
                "started_at": ago(hours=2).isoformat(), "restarts": 3,
                "image": "jc21/nginx-proxy-manager:latest"}
    started = ago(minutes=4) if STATE["scenario"] == "empty" else ago(days=6)
    return {"exists": True, "running": True, "status": "running",
            "started_at": started.isoformat(), "restarts": 0,
            "image": "jc21/nginx-proxy-manager:latest"}


SAMPLE_LOG = """\
[Global   ] › ✔  Backend PID 7 online
[Migrate  ] › info Current database version: none
[Setup    ] › info Added Certbot plugins certbot-dns-cloudflare
[IP Ranges] › info Fetching https://www.cloudflare.com/ips-v4
[SSL      ] › info Renew Timer initialized
[Global   ] › info Backend PID 7 listening on port 3000 ...
172.19.0.1 - admin@blockey.ir "GET /api/nginx/proxy-hosts HTTP/1.1" 200 1841 "python-httpx/0.27.0"
172.19.0.1 - admin@blockey.ir "POST /api/nginx/proxy-hosts HTTP/1.1" 201 498 "python-httpx/0.27.0"
[Nginx    ] › info Reloading Nginx
2026/08/23 18:15:07 [warn] 148#148: *2043 upstream server temporarily disabled while \
connecting to upstream, server: metrics.blockey.ir, upstream: "http://10.50.0.4:3000/"
2026/08/23 18:15:07 [error] 148#148: *2043 connect() failed (110: Connection timed out) while \
connecting to upstream, server: shop.blockey.ir, upstream: "http://10.50.0.5:4000/"
172.70.92.11 - - "GET / HTTP/2.0" 502 559 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
172.71.14.203 - - "GET /api/health HTTP/2.0" 200 76 "Mozilla/5.0 (X11; Linux x86_64)"
[SSL      ] › info Nothing to renew — 1 certificate, next expiry 14 Aug 2040\
"""


def _fake_logs(container: str, lines: int = 100) -> str:
    body = SAMPLE_LOG.splitlines()
    return "\n".join(body[-lines:]) if lines < len(body) else SAMPLE_LOG


_keys = {"n": 0}


def _fake_keypair() -> wg.KeyPair:
    _keys["n"] += 1
    n = _keys["n"]
    return wg.KeyPair(
        private_key=f"previewPrivateKey{n:02d}PaddedToFortyFourChars=",
        public_key=f"previewPublicKey{n:02d}PaddedOutToFortyFourChars=",
    )


def _check(key, title, level, detail="", remedy="") -> health.Check:
    return health.Check(key=key, title=title, level=level, detail=detail, remedy=remedy)


async def _fake_health(config, peers=None) -> health.HealthReport:
    L = health.Level
    if STATE["scenario"] == "degraded":
        checks = [
            _check("wg_installed", "WireGuard installed", L.OK, "wg 1.0.20210914"),
            _check("wg_interface", "Interface wg0 up", L.FAIL, "wg0 does not exist",
                   "Run `wg-quick up wg0`, then check `systemctl status wg-quick@wg0`."),
            _check("ip_forward", "IP forwarding enabled", L.OK, "net.ipv4.ip_forward = 1"),
            _check("fw_rules", "Docker to WireGuard rules", L.FAIL,
                   "forwarding or NAT rules are missing for br-1a2b3c4d (172.19.0.0/16)",
                   "Run `systemctl start edgekit-firewall` (or `edgekit provision`)."),
            _check("npm_container", "Nginx Proxy Manager container", L.FAIL,
                   "container is exited (code 137)",
                   "Check `docker logs npm-app --tail 100`, then "
                   "`cd /opt/nginx-proxy-manager && docker compose up -d`."),
            _check("cert_expiry", "Origin certificate valid", L.WARN,
                   "*.blockey.ir expires in 12 days"),
        ]
    elif STATE["scenario"] == "healthy":
        checks = [
            _check("wg_installed", "WireGuard installed", L.OK, "wg 1.0.20210914"),
            _check("wg_interface", "Interface wg0 up", L.OK,
                   "10.50.0.1, listening on UDP 51820, 5 peers configured"),
            _check("ip_forward", "IP forwarding enabled", L.OK, "net.ipv4.ip_forward = 1"),
            _check("fw_rules", "Docker to WireGuard rules", L.OK,
                   "br-1a2b3c4d 172.19.0.0/16 -> 10.50.0.0/24"),
            _check("npm_container", "Nginx Proxy Manager container", L.OK,
                   "running (jc21/nginx-proxy-manager:latest)"),
            _check("npm_api", "NPM API credentials", L.OK,
                   "token accepted, 5 proxy hosts, 1 certificate"),
            _check("npm_reach", "Peer reachability from the container", L.OK,
                   "all 4 upstreams answered"),
            _check("local_tls", "Local TLS with SNI", L.OK,
                   "all 5 hosts served the origin certificate on 127.0.0.1:443"),
            _check("public_https", "Public HTTPS through Cloudflare", L.OK,
                   "retro 200, api 200, nas 200, metrics 200, edgekit 200"),
            _check("cert_expiry", "Origin certificate valid", L.OK,
                   "*.blockey.ir, expires 14 Aug 2040"),
        ]
    elif STATE["scenario"] == "empty":
        checks = [
            _check("wg_installed", "WireGuard installed", L.OK, "wg 1.0.20210914"),
            _check("wg_interface", "Interface wg0 up", L.OK, "10.50.0.1, 0 peers configured"),
            _check("ip_forward", "IP forwarding enabled", L.OK, "net.ipv4.ip_forward = 1"),
            _check("fw_rules", "Docker to WireGuard rules", L.OK,
                   "br-1a2b3c4d 172.19.0.0/16 -> 10.50.0.0/24"),
            _check("npm_container", "Nginx Proxy Manager container", L.OK,
                   "running (jc21/nginx-proxy-manager:latest)"),
            _check("npm_api", "NPM API credentials", L.OK, "token accepted, 0 proxy hosts"),
            _check("cert_expiry", "Origin certificate valid", L.WARN,
                   "no certificate installed",
                   "Create one in Cloudflare under SSL/TLS -> Origin Server, then paste it "
                   "into Settings."),
        ]
    else:
        checks = [
            _check("wg_installed", "WireGuard installed", L.OK, "wg 1.0.20210914"),
            _check("wg_interface", "Interface wg0 up", L.OK,
                   "10.50.0.1, listening on UDP 51820, 5 peers configured"),
            _check("ip_forward", "IP forwarding enabled", L.OK, "net.ipv4.ip_forward = 1"),
            _check("fw_rules", "Docker to WireGuard rules", L.FAIL,
                   "forwarding or NAT rules are missing for br-1a2b3c4d (172.19.0.0/16)",
                   "Run `systemctl start edgekit-firewall` (or `edgekit provision`). The rules "
                   "must name the network npm-app is on, not the default bridge."),
            _check("npm_container", "Nginx Proxy Manager container", L.OK,
                   "running (jc21/nginx-proxy-manager:latest)"),
            _check("npm_api", "NPM API credentials", L.OK,
                   "token accepted, 5 proxy hosts, 1 certificate"),
            _check("npm_reach", "Peer reachability from the container", L.WARN,
                   "3 of 4 upstreams answered; 10.50.0.5:4000 timed out",
                   "docker exec npm-app curl -I --connect-timeout 5 http://10.50.0.5:4000"),
            _check("local_tls", "Local TLS with SNI", L.OK,
                   "all 5 hosts served the origin certificate on 127.0.0.1:443"),
            _check("public_https", "Public HTTPS through Cloudflare", L.OK,
                   "retro 200, api 200, nas 200, metrics 200, edgekit 200"),
            _check("cert_expiry", "Origin certificate valid", L.OK,
                   "*.blockey.ir, expires 14 Aug 2040"),
        ]
    return health.HealthReport(checks=checks)


def _fake_cloud_firewall(config) -> health.Check:
    if STATE["scenario"] == "healthy":
        return _check("cloud_firewall", "Cloud firewall", health.Level.OK,
                      "UDP 51820 and TCP 80/443 reachable from outside")
    return _check(
        "cloud_firewall", "Cloud firewall (manual)", health.Level.WARN,
        "edgekit cannot see your cloud provider's firewall",
        "Open inbound TCP 22, UDP 51820, TCP 80, TCP 443. Keep closed: TCP 8181, TCP 8099.",
    )


def install_stubs() -> None:
    wg.status = _fake_status
    wg.interface_up = lambda interface: STATE["scenario"] != "degraded"
    wg.interface_exists = lambda interface: STATE["scenario"] != "degraded"
    wg.apply_config = lambda interface: None
    wg.generate_keypair = _fake_keypair
    wg.generate_preshared_key = lambda: "previewPresharedKeyPaddedToFortyFourChars0="
    dockerx.container_state = _fake_container_state
    dockerx.logs = _fake_logs
    health.run_all = _fake_health
    health.cloud_firewall_reminder = _fake_cloud_firewall


# ------------------------------------------------------------------ preview routes


def preview_router() -> APIRouter:
    """Shortcuts that only exist here: sign in without typing, and switch scenario."""
    router = APIRouter(prefix="/_preview")

    @router.get("/login")
    async def quick_login(request: Request, next: str = "/"):
        with db_module.session_scope() as db:
            user = db.query(User).filter_by(username="admin").one()
            token = deps.get_sessions().issue(user.id, user.username)
        response = RedirectResponse(next, status_code=303)
        response.set_cookie(deps.SESSION_COOKIE, token, httponly=True, samesite="strict")
        return response

    @router.get("/scenario/{name}")
    async def switch(name: str, next: str = "/"):
        seed(name)
        return RedirectResponse(next, status_code=303)

    return router


# ------------------------------------------------------------------------- app

install_stubs()
CONFIG.save()
db_module.init_db()
seed(os.environ.get("EDGEKIT_PREVIEW_SCENARIO", "populated"))

app = create_app(CONFIG)
app.include_router(preview_router())
