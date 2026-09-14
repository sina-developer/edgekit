"""Jobs the panel starts run outside it, and report how they ended."""

from __future__ import annotations

import subprocess

import pytest

from edgekit import jobs
from edgekit.system.shell import Result


@pytest.fixture
def logs(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "LOG_DIR", tmp_path)
    return tmp_path


def test_the_command_captures_output_and_exit_status(logs, monkeypatch):
    fake = logs / "fake-edgekit"
    fake.write_text('#!/bin/sh\necho "args: $*"\nexit 3\n')
    fake.chmod(0o755)

    completed = subprocess.run(
        jobs.command("update", ["update", "--skip-provision"], executable=str(fake)), check=False
    )
    monkeypatch.setattr(jobs, "service_active", lambda unit: False)
    state = jobs.state("update")

    assert completed.returncode == 3
    assert state.exit_code == 3
    assert state.output == "args: update --skip-provision"


def test_a_running_job_has_no_exit_code_yet(logs, monkeypatch):
    (logs / "update.log").write_text("Fetching…\n")
    monkeypatch.setattr(jobs, "service_active", lambda unit: True)

    state = jobs.state("update")

    assert state.running is True
    assert state.exit_code is None
    assert state.output == "Fetching…"


def test_a_job_that_never_ran_is_idle(logs, monkeypatch):
    monkeypatch.setattr(jobs, "service_active", lambda unit: False)

    state = jobs.state("update")

    assert (state.running, state.exit_code, state.output) == (False, None, "")


def test_launch_starts_a_transient_unit_with_a_fresh_log(logs, monkeypatch):
    """Owned by systemd, not the panel — a panel restart must not kill the update."""
    (logs / "update.log").write_text("the previous run\n")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(jobs, "has", lambda binary: True)
    monkeypatch.setattr(jobs, "service_active", lambda unit: False)
    monkeypatch.setattr(
        jobs, "run", lambda argv, **kw: calls.append(tuple(argv)) or Result(tuple(argv), 0, "", "")
    )

    jobs.launch("update", ["update"])

    argv = calls[0]
    assert argv[0] == "systemd-run"
    assert "--unit=edgekit-update" in argv
    assert "--collect" in argv
    assert argv[-1] == "update"
    assert (logs / "update.log").read_text() == ""


def test_a_second_launch_while_one_runs_is_refused(logs, monkeypatch):
    monkeypatch.setattr(jobs, "has", lambda binary: True)
    monkeypatch.setattr(jobs, "service_active", lambda unit: True)

    with pytest.raises(jobs.JobError, match="already running"):
        jobs.launch("update", ["update"])


def test_without_systemd_run_the_error_names_the_ssh_command(logs, monkeypatch):
    monkeypatch.setattr(jobs, "has", lambda binary: False)

    with pytest.raises(jobs.JobError, match="sudo edgekit update"):
        jobs.launch("update", ["update"])
