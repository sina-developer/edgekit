"""Existing installs without a Cloudflare token are asked for one, not failed."""

from __future__ import annotations

import logging
import sys

import pytest

from edgekit import cli


class Stdin:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.fixture
def no_token(config):
    config.cloudflare.api_token = ""
    config.cloudflare.enabled = False
    return config


@pytest.fixture
def configured(monkeypatch):
    calls: list[bool] = []

    def configure(config, ask_mode=True):
        calls.append(ask_mode)
        config.cloudflare.api_token = "new-token"
        config.cloudflare.enabled = True

    monkeypatch.setattr("edgekit.wizard.configure_cloudflare", configure)
    monkeypatch.setattr("edgekit.config.Config.save", lambda self, path=None: None)
    return calls


def test_at_a_terminal_a_missing_token_is_asked_for(no_token, configured, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Stdin(tty=True))
    monkeypatch.setattr("edgekit.cli.typer.confirm", lambda *a, **k: True)

    cli._offer_cloudflare_token(no_token)

    assert configured == [True]
    assert no_token.cloudflare.api_token == "new-token"


def test_without_a_terminal_nobody_is_asked(no_token, configured, monkeypatch):
    """The panel's update job has no terminal; provisioning names the command instead."""
    monkeypatch.setattr(sys, "stdin", Stdin(tty=False))

    cli._offer_cloudflare_token(no_token)

    assert configured == []


def test_an_install_that_has_a_token_is_not_asked(config, configured, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Stdin(tty=True))

    cli._offer_cloudflare_token(config)

    assert configured == []


def test_declining_changes_nothing(no_token, configured, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Stdin(tty=True))
    monkeypatch.setattr("edgekit.cli.typer.confirm", lambda *a, **k: False)

    cli._offer_cloudflare_token(no_token)

    assert configured == []
    assert no_token.cloudflare.api_token == ""


@pytest.fixture
def reprovisioned(monkeypatch):
    from edgekit.services.provision import ProvisionReport

    runs: list[tuple[str, object]] = []

    def run(config, only=None, **flags):
        runs.append((config.tls.mode, only))
        return ProvisionReport()

    monkeypatch.setattr(cli, "_run_provisioner", run)
    monkeypatch.setattr("edgekit.config.Config.save", lambda self, path=None: None)
    return runs


def _report(cloudflare_525: bool):
    from edgekit.services.provision import ProvisionReport

    return ProvisionReport(cloudflare_525=cloudflare_525)


def test_a_525_offers_direct_mode_and_applies_it(config, reprovisioned, monkeypatch):
    """Cloudflare cannot reach the server; the mode that does not need it is one yes away."""
    monkeypatch.setattr(sys, "stdin", Stdin(tty=True))
    monkeypatch.setattr("edgekit.cli.typer.confirm", lambda *a, **k: True)

    report = cli._offer_direct_mode(config, _report(True))

    assert config.tls.mode == "direct"
    assert reprovisioned == [("direct", cli.TLS_STEPS)]
    assert report.cloudflare_525 is False


def test_declining_direct_mode_changes_nothing(config, reprovisioned, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Stdin(tty=True))
    monkeypatch.setattr("edgekit.cli.typer.confirm", lambda *a, **k: False)

    cli._offer_direct_mode(config, _report(True))

    assert config.tls.mode == "proxied"
    assert reprovisioned == []


@pytest.mark.parametrize("tty,cloudflare_525", [(False, True), (True, False)])
def test_direct_mode_is_only_offered_at_a_terminal_after_a_525(
    config, reprovisioned, monkeypatch, tty, cloudflare_525
):
    monkeypatch.setattr(sys, "stdin", Stdin(tty=tty))

    def must_not_ask(*a, **k):
        raise AssertionError("nothing to offer")

    monkeypatch.setattr("edgekit.cli.typer.confirm", must_not_ask)

    cli._offer_direct_mode(config, _report(cloudflare_525))

    assert config.tls.mode == "proxied"
    assert reprovisioned == []


def test_records_marked_file_only_stay_off_the_console():
    record = logging.LogRecord("edgekit", logging.ERROR, __file__, 1, "failed", None, None)
    assert cli._for_console(record) is True

    record.console = False
    assert cli._for_console(record) is False
