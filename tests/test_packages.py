"""apt handling — the parts that have to survive a busy or slow server."""

from __future__ import annotations

import pytest

from edgekit.system import packages
from edgekit.system.shell import CommandError, Result

LOCK_ERROR = (
    "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 223605 "
    "(unattended-upgr)\n"
    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another "
    "process using it?"
)


@pytest.fixture(autouse=True)
def instant(monkeypatch):
    """Neither the poll loop nor the retry backoff should slow the suite down."""
    monkeypatch.setattr(packages.time, "sleep", lambda _seconds: None)
    packages._apt_has_lock_timeout.cache_clear()


@pytest.fixture
def unlocked(monkeypatch):
    monkeypatch.setattr(packages, "apt_lock_holder", lambda: None)


def _result(argv, returncode=0, stdout="", stderr=""):
    return Result(tuple(str(a) for a in argv), returncode, stdout, stderr)


def test_apt_retries_while_another_process_holds_the_lock(monkeypatch, unlocked):
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append([str(a) for a in argv])
        if argv[0] != "apt-get":
            return _result(argv)  # the apt-version probe
        if len([c for c in calls if c[0] == "apt-get"]) < 3:
            return _result(argv, 100, stderr=LOCK_ERROR)
        return _result(argv)

    monkeypatch.setattr(packages, "run", fake_run)
    result = packages.apt(["install", "-y", "wireguard"], timeout=900)

    assert result.ok
    assert len([c for c in calls if c[0] == "apt-get"]) == 3
    assert calls[-1][-1] == "wireguard"


def test_apt_gives_up_immediately_on_a_real_failure(monkeypatch, unlocked):
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append([str(a) for a in argv])
        if argv[0] != "apt-get":
            return _result(argv)
        return _result(argv, 100, stderr="E: Unable to locate package bogus")

    monkeypatch.setattr(packages, "run", fake_run)
    with pytest.raises(CommandError):
        packages.apt(["install", "-y", "bogus"], timeout=900)

    apt_calls = [c for c in calls if c[0] == "apt-get"]
    assert len(apt_calls) == 1, "a missing package is not worth retrying"


def test_apt_stops_retrying_once_the_deadline_passes(monkeypatch, unlocked):
    monkeypatch.setattr(packages, "APT_LOCK_WAIT", 0)

    def always_locked(argv, **_kwargs):
        if argv[0] != "apt-get":
            return _result(argv)
        return _result(argv, 100, stderr=LOCK_ERROR)

    monkeypatch.setattr(packages, "run", always_locked)
    with pytest.raises(CommandError):
        packages.apt(["update", "-qq"], timeout=600)


def test_apt_argv_asks_apt_to_wait_when_apt_understands_the_option(monkeypatch):
    monkeypatch.setattr(packages, "_apt_has_lock_timeout", lambda: True)
    argv = packages.apt_argv(["update", "-qq"])
    assert argv[0] == "apt-get"
    assert f"DPkg::Lock::Timeout={packages.APT_LOCK_WAIT}" in argv
    assert argv[-2:] == ["update", "-qq"]


def test_apt_argv_omits_the_option_on_apt_older_than_2(monkeypatch):
    monkeypatch.setattr(packages, "_apt_has_lock_timeout", lambda: False)
    argv = packages.apt_argv(["update", "-qq"])
    assert not any("Lock::Timeout" in arg for arg in argv)
    assert "Acquire::Retries=3" in argv


def test_apt_has_lock_timeout_compares_the_installed_apt_version(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        seen.append(argv)
        if argv[0] == "dpkg-query":
            return _result(argv, stdout="2.4.11\n")
        return _result(argv)  # dpkg --compare-versions succeeded

    monkeypatch.setattr(packages, "run", fake_run)
    assert packages._apt_has_lock_timeout() is True
    assert ["dpkg", "--compare-versions", "2.4.11", "ge", "2.0"] in seen


def test_wait_for_apt_lock_returns_once_the_holder_finishes(monkeypatch):
    holders = iter(["223605", "223605", None, None])
    monkeypatch.setattr(packages, "apt_lock_holder", lambda: next(holders))
    packages.wait_for_apt_lock(deadline=packages.time.monotonic() + 60)


def test_apt_lock_holder_reads_the_pid_from_fuser(monkeypatch, tmp_path):
    lock = tmp_path / "lock-frontend"
    lock.write_text("")
    monkeypatch.setattr(packages, "APT_LOCK_FILES", (str(lock),))
    monkeypatch.setattr(packages, "has", lambda binary: binary == "fuser")
    monkeypatch.setattr(
        packages, "run", lambda argv, **_k: _result(argv, stdout=" 223605 223610\n")
    )
    assert packages.apt_lock_holder() == "223605"


def test_apt_lock_holder_is_none_when_nothing_holds_it(monkeypatch, tmp_path):
    monkeypatch.setattr(packages, "APT_LOCK_FILES", (str(tmp_path / "absent"),))
    monkeypatch.setattr(packages, "has", lambda binary: binary == "fuser")
    monkeypatch.setattr(packages, "run", lambda argv, **_k: _result(argv, 1))
    assert packages.apt_lock_holder() is None
