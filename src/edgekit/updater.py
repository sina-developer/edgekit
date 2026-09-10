"""Fetch a newer edgekit tree and install it into the running virtualenv.

Used by ``edgekit update``. The existing config, database, and panel accounts are never
touched here — those live under /etc/edgekit and /var/lib/edgekit, outside the package.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from .system.shell import CommandError, has, run

DEFAULT_REPO = "https://github.com/sina-developer/edgekit.git"
DEFAULT_REF = "master"

#: pip's 15s default read timeout gives up mid-download on a congested link to PyPI, and a
#: half-finished update is worse than a slow one — so wait longer and try again.
PIP_TIMEOUT = os.environ.get("EDGEKIT_PIP_TIMEOUT", "60")
PIP_RETRIES = os.environ.get("EDGEKIT_PIP_RETRIES", "5")
PIP_ATTEMPTS = int(os.environ.get("EDGEKIT_PIP_ATTEMPTS", "3"))


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


def pip_options() -> list[str]:
    options = [
        "--disable-pip-version-check",
        "--timeout",
        PIP_TIMEOUT,
        "--retries",
        PIP_RETRIES,
    ]
    index = os.environ.get("EDGEKIT_PIP_INDEX_URL", "").strip()
    if index:
        host = index.split("://", 1)[-1].split("/", 1)[0]
        options += ["--index-url", index, "--trusted-host", host]
    extra = os.environ.get("EDGEKIT_PIP_EXTRA_INDEX_URL", "").strip()
    if extra:
        options += ["--extra-index-url", extra]
    return options


#: pip's wording when the index has no build of something for this interpreter. Retrying
#: that is pointless — the answer is deterministic — and it costs minutes to learn nothing.
_RESOLUTION_MARKERS = (
    "resolutionimpossible",
    "no matching distribution",
    "no matching distributions",
)


def _is_resolution_failure(result) -> bool:
    text = f"{result.stdout}\n{result.stderr}".lower()
    return any(marker in text for marker in _RESOLUTION_MARKERS)


def install_package(source: Path) -> None:
    """Reinstall this tree into the virtualenv that is running ``edgekit``."""
    source = Path(source)
    if not (source / "pyproject.toml").is_file():
        raise FileNotFoundError(f"{source} has no pyproject.toml")
    argv = [sys.executable, "-m", "pip", "install", *pip_options(), "--upgrade", str(source)]
    for attempt in range(1, PIP_ATTEMPTS + 1):
        result = run(argv, timeout=900)
        if result.ok:
            return
        if _is_resolution_failure(result):
            raise RuntimeError(
                f"pip found no usable build of a dependency for Python "
                f"{sys.version_info.major}.{sys.version_info.minor} on this machine. "
                "This is not a network problem, so retrying will not help. Reinstall "
                "edgekit against a Python the dependencies publish wheels for, or install "
                "build-essential, python3-dev and libffi-dev so pip can build them.\n\n"
                + (result.stderr or result.stdout).strip()[-800:]
            )
        if attempt == PIP_ATTEMPTS:
            raise RuntimeError(str(CommandError(result)))
        time.sleep(attempt * 10)


def _head_sha(dest: Path) -> str:
    result = run(["git", "-C", str(dest), "rev-parse", "--short", "HEAD"], check=True)
    return result.stdout.strip()
