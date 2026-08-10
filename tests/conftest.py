"""Test fixtures.

``EDGEKIT_ROOT`` is set before any edgekit import because ``edgekit.paths`` resolves the
filesystem layout at module import time. Everything the suite touches therefore lands in a
temporary directory, never in /etc or /var.
"""

from __future__ import annotations

import os
import tempfile

_TEST_ROOT = tempfile.mkdtemp(prefix="edgekit-tests-")
os.environ["EDGEKIT_ROOT"] = _TEST_ROOT

import pytest  # noqa: E402

from edgekit import db as db_module  # noqa: E402
from edgekit.config import Config  # noqa: E402
from edgekit.models import Base  # noqa: E402
from edgekit.system import wireguard as wg  # noqa: E402


@pytest.fixture(scope="session")
def test_root() -> str:
    return _TEST_ROOT


@pytest.fixture
def config() -> Config:
    config = Config()
    config.server.public_ip = "203.0.113.10"
    config.server.hostname = "edge-test"
    config.wireguard.subnet = "10.50.0.0/24"
    config.wireguard.private_key = "aFakePrivateKeyThatIs44CharactersLongForTest="
    config.wireguard.public_key = "vQ8c+XmHJWHtiOAkmiX+zHZAOxyC7W+LgijwGmo14yU="
    config.npm.admin_email = "admin@example.com"
    config.npm.admin_password = "npm-secret-password"
    config.cloudflare.enabled = True
    config.cloudflare.zone_name = "example.com"
    config.cloudflare.zone_id = "zone123"
    config.cloudflare.api_token = "cf-token"
    return config


@pytest.fixture
def clean_db():
    """Empty schema per test, with no session left open.

    Web tests need this rather than ``db_session``: each request opens its own session, and
    SQLite permits a single writer, so a fixture holding an open write transaction would
    deadlock every request against the busy timeout.
    """
    engine = db_module.get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def db_session(clean_db):
    """A clean database plus an open session, for testing services directly."""
    with db_module.session_scope() as session:
        yield session


@pytest.fixture
def fake_wg(monkeypatch):
    """Stub the `wg` binary.

    The real one is absent on developer machines and irrelevant to the logic under test —
    what matters is that key material flows through correctly, not that libsodium works.
    """
    counter = {"n": 0}

    def generate_keypair() -> wg.KeyPair:
        counter["n"] += 1
        index = counter["n"]
        return wg.KeyPair(
            private_key=f"privateKeyNumber{index:02d}PaddedToFortyFourChars=",
            public_key=f"publicKeyNumber{index:02d}PaddedOutToFortyFourChar=",
        )

    applied: list[str] = []

    monkeypatch.setattr(wg, "generate_keypair", generate_keypair)
    monkeypatch.setattr(
        wg, "generate_preshared_key", lambda: "presharedKeyPaddedToFortyFourChars000000000="
    )
    monkeypatch.setattr(wg, "apply_config", lambda interface: applied.append(interface))
    monkeypatch.setattr(wg, "status", lambda interface: [])
    return applied
