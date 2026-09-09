"""Settings: WireGuard, Cloudflare, NPM credentials, certificate, and re-provisioning."""

from __future__ import annotations

import logging
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Config
from ...models import AuditLog, ProxyHost, User
from ...services import certificates
from ...services.cloudflare import CloudflareClient, CloudflareError
from ...services.hosts import SETTING_CERT_EXPIRY, SETTING_CERT_ID, SETTING_CERT_NAME, get_setting
from ...services.peers import PeerService
from ...services.provision import Provisioner
from ..deps import current_user, get_config, get_db, reload_config, verify_csrf
from ..templating import templates

log = logging.getLogger("edgekit.web.settings")

router = APIRouter(prefix="/settings")


def _redirect(message: str = "", error: str = "") -> RedirectResponse:
    query = f"?notice={message}" if message else (f"?error={error}" if error else "")
    return RedirectResponse(f"/settings{query}", status_code=303)


def _as_query(text: str) -> str:
    """Fit an exception into a query string; certificate errors carry punctuation."""
    return quote_plus(" ".join(str(text).split())[:400])


@router.get("")
async def settings_page(
    request: Request,
    notice: str | None = None,
    error: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "config": config,
            "notice": notice,
            "error": error,
            "cert_id": get_setting(db, SETTING_CERT_ID),
            "cert_name": get_setting(db, SETTING_CERT_NAME),
            "cert_expiry": get_setting(db, SETTING_CERT_EXPIRY),
        },
    )


@router.post("/server", dependencies=[Depends(verify_csrf)])
async def update_server(
    public_ip: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    config.server.public_ip = public_ip.strip()
    config.save()
    db.add(AuditLog(actor=user.username, action="settings.server", target=public_ip.strip()))
    reload_config()
    return _redirect(message="Server+settings+saved")


@router.post("/wireguard", dependencies=[Depends(verify_csrf)])
async def update_wireguard(
    listen_port: int = Form(...),
    persistent_keepalive: int = Form(25),
    mtu: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    # The subnet is intentionally not editable here: changing it would strand every peer's
    # address. Widening it is a `edgekit provision` operation with peer re-issue.
    try:
        config.wireguard.listen_port = int(listen_port)
        config.wireguard.persistent_keepalive = int(persistent_keepalive)
        config.wireguard.mtu = int(mtu) if mtu.strip() else None
    except ValueError as exc:
        return _redirect(error=_as_query(exc))

    config.save()
    PeerService(db, config).sync()
    db.add(AuditLog(actor=user.username, action="settings.wireguard", target="wg"))
    reload_config()
    return _redirect(message="WireGuard+settings+applied")


@router.post("/cloudflare", dependencies=[Depends(verify_csrf)])
async def update_cloudflare(
    enabled: bool = Form(False),
    zone_name: str = Form(""),
    api_token: str = Form(""),
    origin_ca_key: str = Form(""),
    proxied: bool = Form(False),
    ssl_mode: str = Form("strict"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    cf = config.cloudflare
    cf.enabled = enabled
    cf.zone_name = zone_name.strip()
    cf.proxied = proxied
    cf.ssl_mode = ssl_mode
    # Blank means "leave the stored secret alone" — the form never echoes secrets back.
    if api_token.strip():
        cf.api_token = api_token.strip()
    if origin_ca_key.strip():
        cf.origin_ca_key = origin_ca_key.strip()

    if cf.enabled and cf.api_token and cf.zone_name:
        try:
            async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
                await client.verify_token()
                cf.zone_id = await client.get_zone_id(cf.zone_name)
        except CloudflareError as exc:
            return _redirect(error=str(exc)[:300])

    config.save()
    db.add(AuditLog(actor=user.username, action="settings.cloudflare", target=cf.zone_name))
    reload_config()
    return _redirect(message="Cloudflare+settings+saved")


@router.post("/npm", dependencies=[Depends(verify_csrf)])
async def update_npm(
    admin_email: str = Form(...),
    admin_password: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    config.npm.admin_email = admin_email.strip()
    if admin_password.strip():
        config.npm.admin_password = admin_password.strip()
    config.save()
    db.add(AuditLog(actor=user.username, action="settings.npm", target=admin_email.strip()))
    reload_config()
    return _redirect(
        message="NPM+credentials+saved.+They+must+match+the+account+inside+NPM."
    )


@router.post("/certificate/issue", dependencies=[Depends(verify_csrf)])
async def issue_certificate(
    force: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    try:
        outcome = await certificates.issue_and_install(
            db, config, actor=user.username, force=force
        )
    except Exception as exc:  # noqa: BLE001 - Cloudflare and NPM errors both land here
        log.error("certificate issuance failed: %s", exc)
        return _redirect(error=_as_query(exc))
    return _redirect(
        message=f"Certificate+{outcome['status']}+(NPM+id+{outcome['certificate_id']})"
    )


@router.post("/certificate/upload", dependencies=[Depends(verify_csrf)])
async def upload_certificate(
    certificate_pem: str = Form(...),
    key_pem: str = Form(...),
    name: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    certificate_pem = certificate_pem.strip() + "\n"
    key_pem = key_pem.strip() + "\n"

    # Validate before touching NPM: a mismatched pair installs cleanly and then fails as a
    # Cloudflare 525, which is a far harder problem to trace back to this form.
    try:
        info = certificates.validate_pair(certificate_pem, key_pem)
    except certificates.CertificateError as exc:
        return _redirect(error=_as_query(exc))

    domains = [h.domain for h in db.scalars(select(ProxyHost))]
    warnings = certificates.coverage_warnings(info, config.cloudflare.zone_name, domains)

    label = name.strip() or certificates.certificate_name(
        config.cloudflare.zone_name or config.server.hostname
    )
    try:
        outcome = await certificates.install_manual_certificate(
            db, config, certificate_pem, key_pem, name=label, actor=user.username
        )
    except Exception as exc:  # noqa: BLE001
        return _redirect(error=_as_query(exc))

    # Remember it so `edgekit provision` can repopulate a rebuilt NPM.
    config.tls.certificate = certificate_pem
    config.tls.certificate_key = key_pem
    config.tls.name = label
    config.save()
    reload_config()

    if outcome["status"] == "unchanged":
        summary = (
            f"That certificate is already installed as NPM id {outcome['certificate_id']}; "
            "nothing changed."
        )
    else:
        summary = (
            f"Installed {', '.join(info.hostnames)} (NPM id {outcome['certificate_id']}), "
            f"expires {info.not_after.date()}"
        )
    return _redirect(message=quote_plus(". ".join([summary, *warnings])))


@router.post("/reprovision", dependencies=[Depends(verify_csrf)])
async def reprovision(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    config: Config = Depends(get_config),
):
    """Re-run the full idempotent provisioner from the panel.

    Runs inline rather than in the background: the operator asked for it and needs the
    result, and a partial provision that nobody watched is worse than a slow page.
    """
    log.info("%s triggered a re-provision", user.username)
    report = await Provisioner(config).run()
    reload_config()

    db.add(
        AuditLog(
            actor=user.username,
            action="provision.rerun",
            target=config.server.public_ip,
            detail=f"{len(report.failures)} failure(s)",
            success=report.ok,
        )
    )
    if report.failures:
        names = ", ".join(f.title for f in report.failures)
        return _redirect(error=f"Provision+finished+with+failures:+{names}")
    return _redirect(message="Provision+completed+successfully")
