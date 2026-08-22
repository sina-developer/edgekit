"""JSON API.

Same session auth as the panel, so it is immediately usable from a logged-in browser or
with a copied cookie, and it gives automation somewhere to hook in without scraping HTML.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import Config
from ...models import Peer, ProxyHost, User
from ...services import health
from ...services.peers import PeerService
from ...system import dockerx
from ...system import wireguard as wg
from ..deps import current_user, get_config, get_db

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/status")
async def status(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    peers = service.list()
    live = service.status_map()
    container = dockerx.container_state(config.npm.container_name)

    return {
        "server": {
            "public_ip": config.server.public_ip,
            "hostname": config.server.hostname,
        },
        "wireguard": {
            "interface": config.wireguard.interface,
            "address": config.wireguard.hub_address,
            "listen_port": config.wireguard.listen_port,
            "up": wg.interface_up(config.wireguard.interface),
            "public_key": config.wireguard.public_key,
            "peers_total": len(peers),
            "peers_connected": sum(
                1 for p in peers if (s := live.get(p.public_key)) and s.connected
            ),
        },
        "npm": {
            "container": config.npm.container_name,
            "running": container.get("running", False),
            "status": container.get("status"),
        },
        "cloudflare": {
            "enabled": config.cloudflare.enabled,
            "zone": config.cloudflare.zone_name,
        },
        "hosts": db.scalar(select(func.count()).select_from(ProxyHost)) or 0,
    }


@router.get("/peers")
async def list_peers(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    live = service.status_map()

    def serialise(peer: Peer) -> dict:
        state = live.get(peer.public_key)
        return {
            "id": peer.id,
            "name": peer.name,
            "description": peer.description,
            "address": peer.address,
            "public_key": peer.public_key,
            "allowed_ips": peer.allowed_ips,
            "enabled": peer.enabled,
            "connected": bool(state and state.connected),
            "endpoint": state.endpoint if state else None,
            "latest_handshake": state.latest_handshake if state else 0,
            "rx_bytes": state.rx_bytes if state else 0,
            "tx_bytes": state.tx_bytes if state else 0,
        }

    return {"peers": [serialise(p) for p in service.list()]}


@router.get("/hosts")
async def list_hosts(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    hosts = db.scalars(select(ProxyHost).order_by(ProxyHost.domain))
    return {
        "hosts": [
            {
                "id": h.id,
                "domain": h.domain,
                "target": h.target,
                "peer_id": h.peer_id,
                "npm_host_id": h.npm_host_id,
                "cloudflare_record_id": h.cloudflare_record_id,
                "force_ssl": h.force_ssl,
            }
            for h in hosts
        ]
    }


@router.get("/health")
async def health_report(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    peers = list(db.scalars(select(Peer)))
    report = await health.run_all(config, peers)
    report.checks.append(health.cloud_firewall_reminder(config))
    return report.as_dict()
