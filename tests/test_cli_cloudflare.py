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


def test_records_marked_file_only_stay_off_the_console():
    record = logging.LogRecord("edgekit", logging.ERROR, __file__, 1, "failed", None, None)
    assert cli._for_console(record) is True

    record.console = False
    assert cli._for_console(record) is False
