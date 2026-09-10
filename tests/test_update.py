"""`edgekit update` must refresh the install without re-running setup."""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from edgekit.cli import app
from edgekit.config import Config
from edgekit.system.shell import Result
from edgekit.updater import fetch_source, install_package, resolve_source, source_dir

runner = CliRunner()


def _ok(argv, stdout: str = "") -> Result:
    return Result(tuple(str(a) for a in argv), 0, stdout, "")


def test_source_dir_honours_prefix(monkeypatch, tmp_path):
    monkeypatch.setenv("EDGEKIT_PREFIX", str(tmp_path / "opt" / "edgekit"))
    assert source_dir() == tmp_path / "opt" / "edgekit" / "src"


def test_fetch_source_clones_when_the_checkout_is_missing(tmp_path, monkeypatch):
    dest = tmp_path / "src"
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if "clone" in argv:
            dest.mkdir()
            (dest / "pyproject.toml").write_text("[project]\nname='edgekit'\n")
        if "rev-parse" in argv:
            return _ok(argv, "abc1234\n")
        return _ok(argv)

    monkeypatch.setattr("edgekit.updater.run", fake_run)
    monkeypatch.setattr("edgekit.updater.has", lambda _binary: True)

    sha = fetch_source("https://github.com/sina-developer/edgekit.git", "master", dest)
    assert sha == "abc1234"
    clone = next(c for c in calls if "clone" in c)
    assert "--depth" in clone
    assert "https://github.com/sina-developer/edgekit.git" in clone
    assert str(dest) in clone


def test_fetch_source_fetches_when_a_checkout_already_exists(tmp_path, monkeypatch):
    dest = tmp_path / "src"
    (dest / ".git").mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if "rev-parse" in argv:
            return _ok(argv, "def5678\n")
        return _ok(argv)

    monkeypatch.setattr("edgekit.updater.run", fake_run)
    monkeypatch.setattr("edgekit.updater.has", lambda _binary: True)

    sha = fetch_source("https://example.com/edgekit.git", "master", dest)
    assert sha == "def5678"
    assert any("clone" in c for c in calls) is False
    assert any("fetch" in c for c in calls)


def test_resolve_source_uses_a_local_tree_without_git(tmp_path, monkeypatch):
    local = tmp_path / "checkout"
    local.mkdir()
    (local / "pyproject.toml").write_text("[project]\nname='edgekit'\n")
    monkeypatch.setenv("EDGEKIT_SOURCE", str(local))

    def boom(*_a, **_k):
        raise AssertionError("git must not run when EDGEKIT_SOURCE is set")

    monkeypatch.setattr("edgekit.updater.fetch_source", boom)
    path, identity = resolve_source("https://example.com/edgekit.git", "master", tmp_path / "src")
    assert path == local
    assert identity == "local"


def test_install_package_upgrades_the_running_venv(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='edgekit'\n")
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append([str(a) for a in argv])
        return _ok(argv)

    monkeypatch.setattr("edgekit.updater.run", fake_run)
    install_package(source)

    assert calls[0][0] == sys.executable
    assert calls[0][1:4] == ["-m", "pip", "install"]
    assert "--upgrade" in calls[0]
    assert str(source) in calls[0]


def _configured(config: Config) -> Config:
    return config


def test_update_refuses_unless_setup_has_already_run(monkeypatch):
    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.load_config", lambda: Config())

    result = runner.invoke(app, ["update"])
    assert result.exit_code == 1
    assert "setup" in result.output.lower()


def test_update_never_runs_the_setup_wizard(monkeypatch, config, tmp_path):
    wizard_calls: list[object] = []
    execd: list[list[str]] = []

    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.require_configured", lambda: _configured(config))
    monkeypatch.setattr("edgekit.updater.source_dir", lambda: tmp_path / "src")
    monkeypatch.setattr(
        "edgekit.updater.resolve_source",
        lambda *a, **k: (tmp_path / "src", "abc1234"),
    )
    monkeypatch.setattr("edgekit.updater.install_package", lambda *_a, **_k: None)
    monkeypatch.setattr("edgekit.wizard.run_wizard", lambda *a, **k: wizard_calls.append(True))

    def fake_execv(path, argv):
        execd.append([str(path), *[str(a) for a in argv]])
        raise SystemExit(0)

    monkeypatch.setattr("edgekit.cli.os.execv", fake_execv)

    result = runner.invoke(app, ["update"])
    assert wizard_calls == []
    assert result.exit_code == 0
    assert execd, "must re-exec the newly installed binary so provision uses new code"
    assert "--resume" in execd[0]


def test_update_resume_reprovisions_and_skips_the_wizard(monkeypatch, config):
    wizard_calls: list[object] = []
    provisioned: list[object] = []
    restarted: list[object] = []

    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.require_configured", lambda: _configured(config))
    monkeypatch.setattr("edgekit.wizard.run_wizard", lambda *a, **k: wizard_calls.append(True))
    monkeypatch.setattr("edgekit.cli.service_unit.install", lambda **k: restarted.append(True))

    class Report:
        ok = True

    monkeypatch.setattr(
        "edgekit.cli._run_provisioner",
        lambda cfg, **k: provisioned.append(cfg) or Report(),
    )

    result = runner.invoke(app, ["update", "--resume", "--sha", "abc1234"])
    assert result.exit_code == 0
    assert wizard_calls == []
    assert restarted == [True]
    assert provisioned == [config]
    assert "abc1234" in result.output
    assert "unchanged" in result.output.lower() or "current settings" in result.output.lower()


def test_update_skip_provision_does_not_reprovision(monkeypatch, config):
    provisioned: list[object] = []
    monkeypatch.setattr("edgekit.cli.is_root", lambda: True)
    monkeypatch.setattr("edgekit.cli.require_configured", lambda: _configured(config))
    monkeypatch.setattr("edgekit.cli.service_unit.install", lambda **k: None)
    monkeypatch.setattr("edgekit.cli._run_provisioner", lambda cfg, **k: provisioned.append(cfg))

    result = runner.invoke(app, ["update", "--resume", "--skip-provision"])
    assert result.exit_code == 0
    assert provisioned == []


class TestResolutionFailures:
    """A missing wheel is deterministic: retrying it just spends minutes on the same answer."""

    def _source(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "pyproject.toml").write_text("[project]\nname='edgekit'\n")
        return source

    def test_a_missing_wheel_fails_immediately_rather_than_retrying(self, tmp_path, monkeypatch):
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append([str(a) for a in argv])
            return Result(
                tuple(str(a) for a in argv),
                1,
                "",
                "ERROR: ResolutionImpossible: cffi has no matching distributions available",
            )

        monkeypatch.setattr("edgekit.updater.run", fake_run)
        monkeypatch.setattr("edgekit.updater.time.sleep", lambda _s: None)

        with pytest.raises(RuntimeError, match="not a network problem"):
            install_package(self._source(tmp_path))

        assert len(calls) == 1

    def test_a_network_failure_is_still_retried(self, tmp_path, monkeypatch):
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append([str(a) for a in argv])
            return Result(tuple(str(a) for a in argv), 1, "", "ReadTimeoutError: pypi.org")

        monkeypatch.setattr("edgekit.updater.run", fake_run)
        monkeypatch.setattr("edgekit.updater.time.sleep", lambda _s: None)

        with pytest.raises(RuntimeError):
            install_package(self._source(tmp_path))

        assert len(calls) == 3
