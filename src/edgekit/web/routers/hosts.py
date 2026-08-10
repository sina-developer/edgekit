"""Proxy host management — guide §16 and §20 as a form."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ...config import Config
from ...models import User
from ...services.hosts import (
    SETTING_CERT_EXPIRY,
    SETTING_CERT_NAME,
    HostService,
    get_setting,
)
from ...services.peers import PeerService
from ..deps import current_user, get_config, get_db, verify_csrf
from ..templating import templates

log = logging.getLogger("edgekit.web.hosts")

router = APIRouter(prefix="/hosts")


def _redirect(message: str = "", error: str = "") -> RedirectResponse:
    query = f"?notice={message}" if message else (f"?error={error}" if error else "")
    return RedirectResponse(f"/hosts{query}", status_code=303)


@router.get("")
async def list_hosts(
    request: Request,
    notice: str | None = None,
    error: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = HostService(db, config)
    return templates.TemplateResponse(
        request,
        "hosts.html",
        {
            "user": user,
            "config": config,
            "hosts": service.list(),
            "peers": PeerService(db, config).list(),
            "certificate_id": service.certificate_id(),
            "cert_name": get_setting(db, SETTING_CERT_NAME),
            "cert_expiry": get_setting(db, SETTING_CERT_EXPIRY),
            "notice": notice,
            "error": error,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_host(
    domain: str = Form(...),
    forward_port: int = Form(...),
    peer_id: str = Form(""),
    forward_host: str = Form(""),
    scheme: str = Form("http"),
    force_ssl: bool = Form(False),
    http2: bool = Form(False),
    websockets: bool = Form(False),
    block_exploits: bool = Form(False),
    manage_dns: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = HostService(db, config)
    try:
        await service.create(
            domain=domain,
            forward_port=forward_port,
            peer_id=int(peer_id) if peer_id.strip() else None,
            forward_host=forward_host.strip() or None,
            scheme=scheme,
            force_ssl=force_ssl,
            http2=http2,
            websockets=websockets,
            block_exploits=block_exploits,
            manage_dns=manage_dns,
            actor=user.username,
        )
    except Exception as exc:  # noqa: BLE001 - surface validation, NPM and CF errors to the form
        log.error("creating host %s failed: %s", domain, exc)
        return _redirect(error=str(exc)[:300])
    return _redirect(message=f"{domain}+published")


@router.post("/{host_id}/update", dependencies=[Depends(verify_csrf)])
async def update_host(
    host_id: int,
    forward_port: int = Form(...),
    peer_id: str = Form(""),
    forward_host: str = Form(""),
    scheme: str = Form("http"),
    force_ssl: bool = Form(False),
    http2: bool = Form(False),
    websockets: bool = Form(False),
    block_exploits: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = HostService(db, config)
    try:
        await service.update(
            host_id,
            peer_id=int(peer_id) if peer_id.strip() else None,
            forward_host=forward_host.strip() or None,
            forward_port=forward_port,
            scheme=scheme,
            force_ssl=force_ssl,
            http2=http2,
            websockets=websockets,
            block_exploits=block_exploits,
            actor=user.username,
        )
    except Exception as exc:  # noqa: BLE001
        return _redirect(error=str(exc)[:300])
    return _redirect(message="Host+updated")


@router.post("/{host_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_host(
    host_id: int,
    remove_dns: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = HostService(db, config)
    try:
        domain = await service.delete(host_id, remove_dns=remove_dns, actor=user.username)
    except Exception as exc:  # noqa: BLE001
        return _redirect(error=str(exc)[:300])
    return _redirect(message=f"Removed+{domain}")


@router.post("/resync", dependencies=[Depends(verify_csrf)])
async def resync(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    outcomes = await HostService(db, config).resync_all()
    failures = [d for d, status in outcomes.items() if status != "ok"]
    log.info("%s resynced %d host(s), %d failed", user.username, len(outcomes), len(failures))
    if failures:
        return _redirect(error=f"Failed:+{',+'.join(failures)}")
    return _redirect(message=f"Resynced+{len(outcomes)}+host(s)")
