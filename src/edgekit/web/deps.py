"""Shared FastAPI dependencies: config, session, current user, CSRF."""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..config import Config, load_config
from ..db import session_scope
from ..models import User
from ..security import SessionManager

log = logging.getLogger("edgekit.web")

SESSION_COOKIE = "edgekit_session"
CSRF_FIELD = "csrf_token"

_config: Config | None = None
_sessions: SessionManager | None = None


def configure(config: Config) -> None:
    """Install the active config. Called by the app factory and after a settings change."""
    global _config, _sessions
    _config = config
    _sessions = SessionManager(config.panel.session_secret, config.panel.session_max_age_seconds)


def get_config() -> Config:
    if _config is None:
        configure(load_config())
    assert _config is not None
    return _config


def reload_config() -> Config:
    configure(load_config())
    return get_config()


def get_sessions() -> SessionManager:
    get_config()
    assert _sessions is not None
    return _sessions


def get_db() -> Iterator[Session]:
    with session_scope() as session:
        yield session


class RedirectToLogin(HTTPException):
    """Signals the exception handler to bounce a browser to the login page."""

    def __init__(self) -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise RedirectToLogin()

    data = get_sessions().read(token)
    if not data:
        raise RedirectToLogin()

    user = db.get(User, data.get("uid"))
    if user is None:
        raise RedirectToLogin()

    request.state.user = user
    return user


# ---------------------------------------------------------------------- CSRF


def csrf_token(request: Request) -> str:
    """Derive a CSRF token from the session cookie.

    Binding the token to the session means it needs no server-side storage and is
    automatically invalidated when the session is.
    """
    session_cookie = request.cookies.get(SESSION_COOKIE, "")
    secret = get_config().panel.session_secret.encode()
    return hmac.new(secret, session_cookie.encode(), hashlib.sha256).hexdigest()


async def verify_csrf(request: Request) -> None:
    """Reject state-changing requests that do not carry a matching token."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    expected = csrf_token(request)
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied:
        form = await request.form()
        supplied = str(form.get(CSRF_FIELD, ""))

    if not supplied or not hmac.compare_digest(supplied, expected):
        log.warning("rejected %s %s: CSRF token mismatch", request.method, request.url.path)
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


def client_key(request: Request) -> str:
    """Identify a client for login throttling.

    Uses the socket peer, not X-Forwarded-For: the panel is meant to be reached directly or
    over an SSH tunnel, and trusting a client-supplied header here would let an attacker
    sidestep the throttle by varying it.
    """
    return request.client.host if request.client else "unknown"
