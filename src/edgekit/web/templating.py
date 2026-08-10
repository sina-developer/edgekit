"""Jinja2 templates for the panel, with shared globals and filters."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .. import __version__
from .deps import csrf_token

TEMPLATE_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


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
