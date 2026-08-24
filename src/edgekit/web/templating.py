"""Jinja2 templates for the panel, with shared globals and filters."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from starlette.requests import Request

from .. import __version__
from .deps import csrf_token

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _chrome(request: Request) -> dict:
    """Values the sidebar and header need on every page.

    Every page renders the sidebar, so this lives here rather than in each route — a route
    that forgets to pass ``config`` must not be able to break the chrome. It is best-effort
    throughout: an unreadable database must not turn a page into a 500, and each piece of
    chrome simply disappears when its value is missing.
    """
    from ..db import session_scope
    from ..models import Peer, ProxyHost
    from .deps import get_config

    chrome: dict = {}

    try:
        config = get_config()
        chrome["site_name"] = (
            config.cloudflare.zone_name or config.server.hostname or "unconfigured"
        )
    except Exception:  # noqa: BLE001 - navigation chrome is never worth a 500
        chrome["site_name"] = "edgekit"

    try:
        with session_scope() as db:
            chrome["peer_count"] = db.scalar(select(func.count()).select_from(Peer)) or 0
            chrome["host_count"] = db.scalar(select(func.count()).select_from(ProxyHost)) or 0
    except Exception:  # noqa: BLE001
        pass

    return chrome


STATIC_DIR = Path(__file__).parent / "static"


def static_url(name: str) -> str:
    """Cache-busted URL for a file in /static.

    Keyed on the file's mtime rather than the package version: a CSS fix that ships without
    a version bump would otherwise never reach a browser that has the old file cached.
    """
    try:
        stamp = int((STATIC_DIR / name).stat().st_mtime)
    except OSError:
        return f"/static/{name}"
    return f"/static/{name}?v={stamp}"


templates = Jinja2Templates(directory=str(TEMPLATE_DIR), context_processors=[_chrome])


def _relative_time(value: dt.datetime | int | None) -> str:
    """Render a timestamp as a compact age, e.g. '3m ago'."""
    if not value:
        return "never"
    if isinstance(value, int | float):
        value = dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)

    seconds = (dt.datetime.now(dt.timezone.utc) - value).total_seconds()
    if seconds < 0:
        return "just now"
    for limit, divisor, unit in (
        (60, 1, "s"),
        (3600, 60, "m"),
        (86400, 3600, "h"),
        (2592000, 86400, "d"),
    ):
        if seconds < limit:
            return f"{int(seconds // divisor)}{unit} ago"
    return value.strftime("%Y-%m-%d")


def _bytes(value: int | None) -> str:
    if not value:
        return "0 B"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PiB"


templates.env.filters["relative_time"] = _relative_time
templates.env.filters["human_bytes"] = _bytes
templates.env.globals["version"] = __version__
templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["static_url"] = static_url
