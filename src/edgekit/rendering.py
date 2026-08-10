"""Jinja2 environment for the config artifacts edgekit generates."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATE_DIR = Path(__file__).parent / "templates"


@lru_cache(maxsize=1)
def env() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        undefined=StrictUndefined,  # a missing variable is a bug, not an empty string
        keep_trailing_newline=True,
        trim_blocks=False,
        autoescape=False,  # these are ini/yaml files, not HTML
    )


def render(template: str, **context) -> str:
    return env().get_template(template).render(**context)
