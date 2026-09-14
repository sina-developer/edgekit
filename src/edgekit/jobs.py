"""Operations the panel starts but must not own.

`edgekit update` restarts edgekit-panel.service and `edgekit uninstall` removes it. Started as
children of the panel, either would be killed along with the panel's cgroup half way
through, and the panel's sandbox (ProtectSystem=full) would stop them writing where they
must. So each runs as a transient systemd unit of its own, with its output and exit status
written to a log the panel can show.
"""

from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from .paths import LOG_DIR
from .system.shell import has, run, service_active

UPDATE = "update"
UNINSTALL = "uninstall"

_EXIT_MARKER = "edgekit-job-exit"
_EXIT_LINE = re.compile(rf"^{_EXIT_MARKER} (\d+)\n?", re.MULTILINE)


class JobError(RuntimeError):
    pass


@dataclass
class JobState:
    running: bool
    #: None while running, or when the job has never run.
    exit_code: int | None
    output: str


def unit_name(job: str) -> str:
    return f"edgekit-{job}"


def log_file(job: str) -> Path:
    return LOG_DIR / f"{job}.log"


def command(job: str, args: list[str], *, executable: str | None = None) -> list[str]:
    """What the transient unit runs: edgekit, with its output and exit status captured."""
    executable = executable or f"{sys.prefix}/bin/edgekit"
    log = shlex.quote(str(log_file(job)))
    script = (
        f'"$0" "$@" > {log} 2>&1; code=$?; echo "{_EXIT_MARKER} $code" >> {log}; exit $code'
    )
    return ["/bin/sh", "-c", script, executable, *args]


def launch(job: str, args: list[str]) -> None:
    if not has("systemd-run"):
        raise JobError(
            "systemd-run is not available, so this cannot be started from the panel. Run "
            f"`sudo edgekit {' '.join(args)}` over SSH instead."
        )
    if service_active(f"{unit_name(job)}.service"):
        raise JobError(f"edgekit {job} is already running")

    path = log_file(job)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")
    result = run(
        [
            "systemd-run",
            f"--unit={unit_name(job)}",
            f"--description=edgekit {job}",
            "--collect",
            "--no-block",
            *command(job, args),
        ]
    )
    if not result.ok:
        raise JobError(f"Could not start edgekit {job}: {result.output}")


def state(job: str, lines: int = 400) -> JobState:
    running = service_active(f"{unit_name(job)}.service")
    try:
        text = log_file(job).read_text(errors="replace")
    except OSError:
        text = ""
    codes = _EXIT_LINE.findall(text)
    output = "\n".join(_EXIT_LINE.sub("", text).rstrip().splitlines()[-lines:])
    exit_code = int(codes[-1]) if codes and not running else None
    return JobState(running=running, exit_code=exit_code, output=output)
