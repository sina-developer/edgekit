"""Secret handling.

Secrets (Cloudflare tokens, NPM credentials, WireGuard private keys) are stored encrypted at
rest with a Fernet key held in a single 0600 file. This does not defend against root on the
box — root can read the key — but it keeps credentials out of config backups, `grep`, log
scrapes, and accidental pastes, which is the realistic threat here.

Encrypted values are marked with the ``enc:`` prefix so a config file can be read at a glance
and so plaintext values written by hand are still accepted.
"""

from __future__ import annotations

import os
import stat

from cryptography.fernet import Fernet, InvalidToken

from .paths import SECRET_KEY_FILE

PREFIX = "enc:"


class SecretError(RuntimeError):
    """Raised when a stored secret cannot be decrypted."""


def _load_or_create_key() -> bytes:
    if SECRET_KEY_FILE.exists():
        key = SECRET_KEY_FILE.read_bytes().strip()
        if key:
            return key

    key = Fernet.generate_key()
    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the outset rather than chmod-ing after the fact, which would
    # leave a window where the key is world-readable.
    fd = os.open(
        SECRET_KEY_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt(value: str | None) -> str | None:
    """Encrypt ``value``. Already-encrypted values pass through unchanged."""
    if value is None or value == "":
        return value
    if value.startswith(PREFIX):
        return value
    token = _fernet().encrypt(value.encode()).decode()
    return PREFIX + token


def decrypt(value: str | None) -> str | None:
    """Decrypt ``value``. Plaintext values (no ``enc:`` prefix) pass through unchanged."""
    if value is None or value == "":
        return value
    if not value.startswith(PREFIX):
        return value
    try:
        return _fernet().decrypt(value[len(PREFIX) :].encode()).decode()
    except InvalidToken as exc:  # pragma: no cover - corrupted state
        raise SecretError(
            f"Could not decrypt a stored secret. The key at {SECRET_KEY_FILE} may have been "
            "replaced or the config restored from a different host."
        ) from exc


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)
