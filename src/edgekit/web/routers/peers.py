"""WireGuard peer management — the panel the guide's §5 and §20 workflows collapse into."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from ...config import Config
from ...models import User
from ...services.peers import PeerError, PeerService
from ...system import wireguard as wg
from ..deps import current_user, get_config, get_db, verify_csrf
from ..templating import templates

log = logging.getLogger("edgekit.web.peers")

router = APIRouter(prefix="/peers")


def _redirect(message: str = "", error: str = "") -> RedirectResponse:
    query = f"?notice={message}" if message else (f"?error={error}" if error else "")
    return RedirectResponse(f"/peers{query}", status_code=303)


@router.get("")
async def list_peers(
    request: Request,
    notice: str | None = None,
    error: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    peers = service.list()
    live = service.status_map()
    try:
        suggested = wg.next_free_address(config.wireguard.subnet, service.taken_addresses())
    except Exception:  # noqa: BLE001 - a full subnet must not break the page
        suggested = ""

    return templates.TemplateResponse(
        request,
        "peers.html",
        {
            "user": user,
            "config": config,
            "peers": peers,
            "live": live,
            "notice": notice,
            "error": error,
            "suggested_address": suggested,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_peer(
    name: str = Form(...),
    description: str = Form(""),
    address: str = Form(""),
    public_key: str = Form(""),
    extra_allowed_ips: str = Form(""),
    keepalive: int = Form(25),
    use_preshared_key: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        peer = service.create(
            name,
            description=description,
            address=address.strip() or None,
            public_key=public_key.strip() or None,
            extra_allowed_ips=extra_allowed_ips,
            keepalive=keepalive,
            use_preshared_key=use_preshared_key,
            actor=user.username,
        )
        db.flush()
        service.sync()
    except PeerError as exc:
        return _redirect(error=str(exc))

    return RedirectResponse(f"/peers/{peer.id}?notice=Peer+created", status_code=303)


@router.get("/{peer_id}")
async def peer_detail(
    request: Request,
    peer_id: int,
    notice: str | None = None,
    error: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        peer = service.get(peer_id)
    except PeerError as exc:
        return _redirect(error=str(exc))

    config_text = qr_svg = None
    render_error = None
    try:
        config_text = service.render_peer_config(peer)
        qr_svg = service.render_peer_qr(peer)
    except PeerError as exc:
        render_error = str(exc)

    live = service.status_map().get(peer.public_key)
    return templates.TemplateResponse(
        request,
        "peer_detail.html",
        {
            "user": user,
            "config": config,
            "peer": peer,
            "live": live,
            "peer_config": config_text,
            "qr_svg": qr_svg,
            "render_error": render_error,
            "notice": notice,
            "error": error,
        },
    )


@router.get("/{peer_id}/config")
async def download_config(
    peer_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    peer = service.get(peer_id)
    body = service.render_peer_config(peer)
    filename = f"{peer.name.replace(' ', '-')}-{config.wireguard.interface}.conf"
    log.info("%s downloaded the config for peer %s", user.username, peer.name)
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{peer_id}/update", dependencies=[Depends(verify_csrf)])
async def update_peer(
    peer_id: int,
    description: str = Form(""),
    extra_allowed_ips: str = Form(""),
    keepalive: int = Form(25),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        service.update(
            peer_id,
            description=description,
            extra_allowed_ips=extra_allowed_ips,
            keepalive=keepalive,
            actor=user.username,
        )
        db.flush()
        service.sync()
    except PeerError as exc:
        return RedirectResponse(f"/peers/{peer_id}?error={exc}", status_code=303)
    return RedirectResponse(f"/peers/{peer_id}?notice=Peer+updated", status_code=303)


@router.post("/{peer_id}/toggle", dependencies=[Depends(verify_csrf)])
async def toggle_peer(
    peer_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        new_state = not service.get(peer_id).enabled
        service.update(peer_id, enabled=new_state, actor=user.username)
        db.flush()
        service.sync()
        state = "enabled" if new_state else "disabled"
    except PeerError as exc:
        return _redirect(error=str(exc))
    return _redirect(message=f"Peer+{state}")


@router.post("/{peer_id}/rotate", dependencies=[Depends(verify_csrf)])
async def rotate_peer(
    peer_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        service.rotate_keys(peer_id, actor=user.username)
        db.flush()
        service.sync()
    except PeerError as exc:
        return RedirectResponse(f"/peers/{peer_id}?error={exc}", status_code=303)
    return RedirectResponse(
        f"/peers/{peer_id}?notice=Keys+rotated.+Reinstall+the+config+on+the+peer.",
        status_code=303,
    )


@router.post("/{peer_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_peer(
    peer_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    service = PeerService(db, config)
    try:
        name = service.delete(peer_id, actor=user.username)
        db.flush()
        service.sync()
    except PeerError as exc:
        return _redirect(error=str(exc))
    return _redirect(message=f"Deleted+{name}")


@router.post("/sync", dependencies=[Depends(verify_csrf)])
async def sync_peers(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    PeerService(db, config).sync()
    log.info("%s triggered a manual wg sync", user.username)
    return _redirect(message="Interface+synchronised")
