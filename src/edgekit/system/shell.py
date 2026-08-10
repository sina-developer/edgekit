"""Subprocess execution.

Everything that shells out goes through :func:`run`, which gives one place to enforce
timeouts, capture output, and log commands. ``shell=True`` is deliberately not offered —
callers pass argument lists, so no command is ever built by string interpolation.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

log = logging.getLogger("edgekit.shell")

DEFAULT_TIMEOUT = 300


class CommandError(RuntimeError):
    """A command exited non-zero while the caller required success."""

    def __init__(self, result: Result) -> None:
        self.result = result
        super().__init__(
            f"`{result.display}` exited {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()[:800]}"
        )


@dataclass(slots=True)
class Result:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def display(self) -> str:
        return " ".join(self.argv)

    @property
    def output(self) -> str:
        return (self.stdout or self.stderr).strip()


def run(
    argv: Sequence[str],
    *,
    check: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    input_text: str | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> Result:
    """Run ``argv`` and capture its output.

    ``check=True`` raises :class:`CommandError` on a non-zero exit; the default returns the
    result so callers can branch on it, which is what most probe-style calls want.
    """
    argv = tuple(str(a) for a in argv)
    log.debug("run: %s", " ".join(argv))

    merged_env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
    if env:
        merged_env.update(env)

    try:
        completed = subprocess.run(  # noqa: S603 - argv is a list, never shell-interpolated
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=merged_env,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError:
        result = Result(argv, 127, "", f"command not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        result = Result(argv, 124, "", f"timed out after {timeout}s")
    else:
        result = Result(argv, completed.returncode, completed.stdout, completed.stderr)

    if not result.ok:
        log.debug("run failed (%s): %s", result.returncode, result.output[:400])
    if check and not result.ok:
        raise CommandError(result)
    return result


def which(binary: str) -> str | None:
    return shutil.which(binary)


def has(binary: str) -> bool:
    return which(binary) is not None


def is_root() -> bool:
    return os.geteuid() == 0


def systemctl(*args: str, check: bool = False) -> Result:
    return run(["systemctl", *args], check=check)


def service_active(unit: str) -> bool:
    return systemctl("is-active", "--quiet", unit).ok


def service_enabled(unit: str) -> bool:
    return systemctl("is-enabled", "--quiet", unit).ok
