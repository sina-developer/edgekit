"""Fetch a newer edgekit tree and install it into the running virtualenv.

Used by ``edgekit update``. The existing config, database, and panel accounts are never
touched here — those live under /etc/edgekit and /var/lib/edgekit, outside the package.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .system.shell import CommandError, has, run

DEFAULT_REPO = "https://github.com/sina-developer/edgekit.git"
DEFAULT_REF = "master"


def default_repo() -> str:
    return os.environ.get("EDGEKIT_REPO") or os.environ.get("EDGEKIT_DEFAULT_REPO") or DEFAULT_REPO


def default_ref() -> str:
    return os.environ.get("EDGEKIT_REF") or DEFAULT_REF


def source_dir() -> Path:
    """Persistent git checkout, next to the venv the installer created."""
    prefix = Path(os.environ.get("EDGEKIT_PREFIX", "/opt/edgekit"))
    return prefix / "src"


def resolve_source(repo: str, ref: str, dest: Path, local: str | None = None) -> tuple[Path, str]:
    """Return ``(path_to_tree, identity)`` — identity is a short SHA, or ``local``."""
    local_path = local if local is not None else os.environ.get("EDGEKIT_SOURCE", "").strip()
    if local_path:
        path = Path(local_path).expanduser().resolve()
        if not (path / "pyproject.toml").is_file():
            raise FileNotFoundError(f"EDGEKIT_SOURCE={path} has no pyproject.toml")
        return path, "local"
    return dest, fetch_source(repo, ref, dest)


def fetch_source(repo: str, ref: str, dest: Path) -> str:
    """Clone or fast-forward ``dest`` to ``ref`` of ``repo``. Returns the short HEAD SHA."""
    if not has("git"):
        raise RuntimeError(
            "git is required for `edgekit update`. Install it with `apt install git`."
        )

    dest = Path(dest)
    try:
        if (dest / ".git").is_dir():
            run(["git", "-C", str(dest), "remote", "set-url", "origin", repo], check=True)
            run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref], check=True)
            run(["git", "-C", str(dest), "checkout", "-f", "--detach", "FETCH_HEAD"], check=True)
        else:
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            run(
                ["git", "clone", "--depth", "1", "--branch", ref, repo, str(dest)],
                check=True,
            )
    except CommandError as exc:
        raise RuntimeError(str(exc)) from exc
    return _head_sha(dest)


def install_package(source: Path) -> None:
    """Reinstall this tree into the virtualenv that is running ``edgekit``."""
    source = Path(source)
    if not (source / "pyproject.toml").is_file():
        raise FileNotFoundError(f"{source} has no pyproject.toml")
    try:
        run(
            [sys.executable, "-m", "pip", "install", "--upgrade", str(source)],
            check=True,
            timeout=600,
        )
    except CommandError as exc:
        raise RuntimeError(str(exc)) from exc


def _head_sha(dest: Path) -> str:
    result = run(["git", "-C", str(dest), "rev-parse", "--short", "HEAD"], check=True)
    return result.stdout.strip()
