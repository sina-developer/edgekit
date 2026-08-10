"""Dashboard and diagnostics."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ...config import Config
from ...models import AuditLog, Peer, ProxyHost, User
from ...services import health
from ...services.hosts import SETTING_CERT_EXPIRY, SETTING_CERT_NAME, get_setting
from ...services.peers import PeerService
from ...system import dockerx
from ...system import wireguard as wg
from ..deps import current_user, get_config, get_db
from ..templating import templates

router = APIRouter()


@router.get("/")
async def index(
    request: Request,
    notice: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    peers = PeerService(db, config).list()
    live = {p.public_key: p for p in wg.status(config.wireguard.interface)}
    hosts = list(db.scalars(select(ProxyHost).order_by(ProxyHost.domain)))
    recent = list(
        db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(12))
    )

    container = dockerx.container_state(config.npm.container_name)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "config": config,
            "notice": notice,
            "peers": peers,
            "live": live,
            "hosts": hosts,
            "recent": recent,
            "container": container,
            "interface_up": wg.interface_up(config.wireguard.interface),
            "cert_name": get_setting(db, SETTING_CERT_NAME),
            "cert_expiry": get_setting(db, SETTING_CERT_EXPIRY),
            "connected_count": sum(
                1 for p in peers if (s := live.get(p.public_key)) and s.connected
            ),
        },
    )


@router.get("/diagnostics")
async def diagnostics(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    peers = list(db.scalars(select(Peer)))
    report = await health.run_all(config, peers)
    report.checks.append(health.cloud_firewall_reminder(config))
    return templates.TemplateResponse(
        request,
        "diagnostics.html",
        {"user": user, "config": config, "report": report},
    )


@router.get("/audit")
async def audit(
    request: Request,
    page: int = 1,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    page = max(1, page)
    per_page = 50
    entries = list(
        db.scalars(
            select(AuditLog)
            .order_by(desc(AuditLog.created_at))
            .offset((page - 1) * per_page)
            .limit(per_page + 1)
        )
    )
    has_next = len(entries) > per_page
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "user": user,
            "config": config,
            "entries": entries[:per_page],
            "page": page,
            "has_next": has_next,
        },
    )


@router.get("/logs")
async def container_logs(
    request: Request,
    lines: int = 200,
    user: User = Depends(current_user),
    config: Config = Depends(get_config),
):
    lines = min(max(lines, 20), 2000)
    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "user": user,
            "config": config,
            "lines": lines,
            "output": dockerx.logs(config.npm.container_name, lines),
        },
    )
