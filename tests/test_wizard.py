"""Setup interview: prompts must wait for the operator, even under ``curl | bash``."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_certificates import make_cert

from edgekit.wizard import attach_stdin_to_tty

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def restore_stdin():
    original = sys.stdin
    original_dunder = sys.__stdin__
    yield
    sys.stdin = original
    sys.__stdin__ = original_dunder


def test_attach_stdin_to_tty_is_noop_when_already_a_tty(restore_stdin, monkeypatch):
    class Tty:
        def isatty(self) -> bool:
            return True

    stdin = Tty()
    monkeypatch.setattr(sys, "stdin", stdin)

    assert attach_stdin_to_tty() is True
    assert sys.stdin is stdin


def test_attach_stdin_to_tty_reads_tty_not_the_pipe(tmp_path, restore_stdin, monkeypatch):
    tty = tmp_path / "tty"
    tty.write_text("203.0.113.10\n")

    r, w = os.pipe()
    os.write(w, b"from-the-pipe-must-not-be-read\n")
    os.close(w)
    monkeypatch.setattr(sys, "stdin", os.fdopen(r))
    monkeypatch.setattr(sys, "__stdin__", sys.stdin)

    assert sys.stdin.isatty() is False
    assert attach_stdin_to_tty(str(tty)) is True
    assert sys.stdin.readline() == "203.0.113.10\n"


def test_attach_stdin_to_tty_returns_false_when_tty_missing(restore_stdin, monkeypatch, tmp_path):
    class Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdin", Pipe())

    assert attach_stdin_to_tty(str(tmp_path / "no-such-tty")) is False


def test_install_sh_reattaches_stdin_so_read_waits_for_the_terminal(tmp_path):
    """``curl | bash`` feeds the script on stdin; ``read`` must not take EOF from that pipe."""
    tty = tmp_path / "tty"
    tty.write_text("203.0.113.10\n")

    script = r"""
    set -euo pipefail
    if [ ! -t 0 ] && [ -r "$EDGEKIT_TTY" ]; then
        exec <"$EDGEKIT_TTY"
    fi
    read -r line
    printf '%s\n' "$line"
    """
    result = subprocess.run(
        ["bash", "-c", script],
        input="this-is-the-curl-pipe-and-must-be-ignored\n",
        capture_output=True,
        text=True,
        env={**os.environ, "EDGEKIT_TTY": str(tty)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "203.0.113.10"


def test_install_sh_reconnects_stdin_before_setup():
    text = (REPO_ROOT / "install.sh").read_text()
    assert "attach_controlling_tty" in text
    assert "exec </dev/tty" in text or "exec < /dev/tty" in text
    # Handover to setup must happen after stdin is the terminal, otherwise
    # the first prompt (public IP) raises EOFError and Click prints "Aborted".
    attach_at = text.index("attach_controlling_tty")
    setup_at = text.index('exec "${BIN}" setup')
    assert attach_at < setup_at


def test_existing_origin_pair_reads_saved_files(tmp_path, monkeypatch, config):
    from edgekit.wizard import existing_origin_pair

    cert, key = make_cert(["*.example.com", "example.com"])
    cert_file = tmp_path / "origin.pem"
    key_file = tmp_path / "origin.key"
    cert_file.write_text(cert)
    key_file.write_text(key)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_CERT_FILE", cert_file)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_KEY_FILE", key_file)

    found = existing_origin_pair(config)
    assert found == (cert, key)


def test_collect_certificate_skips_paste_when_keys_exist_and_renew_is_declined(
    tmp_path, monkeypatch, config
):
    from edgekit.wizard import _collect_certificate

    cert, key = make_cert(["*.example.com", "example.com"])
    cert_file = tmp_path / "origin.pem"
    key_file = tmp_path / "origin.key"
    cert_file.write_text(cert)
    key_file.write_text(key)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_CERT_FILE", cert_file)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_KEY_FILE", key_file)
    monkeypatch.setattr("edgekit.wizard.env", lambda *_a, **_k: "")

    questions: list[str] = []

    def fake_confirm(question, default=True):
        questions.append(question)
        return False

    monkeypatch.setattr("edgekit.wizard.Confirm.ask", fake_confirm)
    monkeypatch.setattr(
        "edgekit.wizard._prompt_pem_paste",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not ask for new keys")),
    )

    _collect_certificate(config, non_interactive=False)

    assert config.tls.certificate == cert
    assert config.tls.certificate_key == key
    assert any("renew" in q.lower() for q in questions)


def test_collect_certificate_asks_for_new_keys_when_renew_is_accepted(
    tmp_path, monkeypatch, config
):
    from edgekit.wizard import _collect_certificate

    old_cert, old_key = make_cert(["*.example.com", "example.com"])
    new_cert, new_key = make_cert(["*.example.com", "example.com"])
    cert_file = tmp_path / "origin.pem"
    key_file = tmp_path / "origin.key"
    cert_file.write_text(old_cert)
    key_file.write_text(old_key)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_CERT_FILE", cert_file)
    monkeypatch.setattr("edgekit.wizard.ORIGIN_KEY_FILE", key_file)
    monkeypatch.setattr("edgekit.wizard.env", lambda *_a, **_k: "")
    monkeypatch.setattr("edgekit.wizard.Confirm.ask", lambda *a, **k: True)

    pastes = [new_cert, new_key]
    monkeypatch.setattr("edgekit.wizard._prompt_pem_paste", lambda _label: pastes.pop(0))

    _collect_certificate(config, non_interactive=False)

    assert config.tls.certificate == new_cert
    assert cert_file.read_text() == new_cert
    assert key_file.read_text() == new_key
