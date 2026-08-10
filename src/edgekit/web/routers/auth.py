"""Login, logout, and password change."""

from __future__ import annotations

import datetime as dt
import logging
import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import AuditLog, User
from ...security import (
    AuthError,
    LoginThrottle,
    check_password_strength,
    hash_password,
    verify_password,
)
from ..deps import (
    SESSION_COOKIE,
    client_key,
    current_user,
    get_config,
    get_db,
    get_sessions,
    verify_csrf,
)
from ..templating import templates

log = logging.getLogger("edgekit.web.auth")

router = APIRouter()
throttle = LoginThrottle()

#: A real hash over a random secret, verified when the username does not exist so that a
#: missing account and a wrong password cost the same wall time.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def _safe_next(target: str | None) -> str:
    """Only allow same-site relative redirects, so ?next= cannot bounce off-site."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


@router.get("/login")
async def login_form(request: Request, next: str = "/"):
    if request.cookies.get(SESSION_COOKIE):
        data = get_sessions().read(request.cookies[SESSION_COOKIE])
        if data:
            return RedirectResponse(_safe_next(next), status_code=303)
    return templates.TemplateResponse(request, "login.html", {"next": _safe_next(next)})


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    key = client_key(request)
    try:
        throttle.check(key)
    except AuthError as exc:
        return templates.TemplateResponse(
            request, "login.html", {"error": str(exc), "next": _safe_next(next)}, status_code=429
        )

    user = db.scalar(select(User).where(User.username == username.strip()))
    # Always run a verification so a missing user and a wrong password take the same time.
    stored_hash = user.password_hash if user else _DUMMY_HASH
    if not verify_password(password, stored_hash) or not user:
        throttle.record_failure(key)
        db.add(
            AuditLog(
                actor=username.strip()[:64],
                action="auth.login",
                target=key,
                success=False,
                detail="invalid credentials",
            )
        )
        log.warning("failed login for %r from %s", username, key)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password", "next": _safe_next(next)},
            status_code=401,
        )

    throttle.record_success(key)
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    db.add(AuditLog(actor=user.username, action="auth.login", target=key, success=True))

    config = get_config()
    token = get_sessions().issue(user.id, user.username)
    destination = "/settings/password" if user.must_change_password else _safe_next(next)
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.panel.session_max_age_seconds,
        httponly=True,
        samesite="strict",
        # The panel is normally reached over an SSH tunnel on plain HTTP, so Secure would
        # break the cookie entirely. Set it when the request itself arrived over TLS.
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(request: Request, user: User = Depends(current_user)):
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    log.info("%s logged out", user.username)
    return response


@router.get("/settings/password")
async def password_form(request: Request, user: User = Depends(current_user)):
    return templates.TemplateResponse(
        request, "password.html", {"user": user, "forced": user.must_change_password}
    )


@router.post("/settings/password", dependencies=[Depends(verify_csrf)])
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    def fail(message: str):
        return templates.TemplateResponse(
            request,
            "password.html",
            {"user": user, "error": message, "forced": user.must_change_password},
            status_code=400,
        )

    if not verify_password(current_password, user.password_hash):
        return fail("Current password is incorrect")
    if new_password != confirm_password:
        return fail("New passwords do not match")
    try:
        check_password_strength(new_password)
    except AuthError as exc:
        return fail(str(exc))

    db_user = db.get(User, user.id)
    db_user.password_hash = hash_password(new_password)
    db_user.must_change_password = False
    db.add(AuditLog(actor=user.username, action="auth.password_change", target=user.username))
    log.info("%s changed their password", user.username)

    return RedirectResponse("/?notice=Password+updated", status_code=303)
