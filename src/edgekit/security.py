"""Panel authentication: password hashing, signed sessions, and login throttling."""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

log = logging.getLogger("edgekit.security")

MIN_PASSWORD_LENGTH = 12
SESSION_SALT = "edgekit.session"


class AuthError(RuntimeError):
    pass


# ---------------------------------------------------------------------- passwords


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (ValueError, TypeError):
        return False


def check_password_strength(password: str) -> None:
    """Length-first policy. Raises :class:`AuthError` describing the first failure.

    Length dominates composition rules for real-world resistance, so the bar is a long
    password rather than a short one with a symbol bolted on.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in {"password", "changeme", "adminadmin", "edgekitadmin"}:
        raise AuthError("That password is too common")
    if len(set(password)) < 5:
        raise AuthError("Password must use at least 5 distinct characters")


def generate_password(length: int = 24) -> str:
    """URL-safe random password, used for the NPM admin account and for `--auto` setup."""
    return secrets.token_urlsafe(length)[:length]


# ---------------------------------------------------------------------- sessions


class SessionManager:
    def __init__(self, secret: str, max_age: int) -> None:
        self._serializer = URLSafeTimedSerializer(secret, salt=SESSION_SALT)
        self.max_age = max_age

    def issue(self, user_id: int, username: str) -> str:
        return self._serializer.dumps({"uid": user_id, "u": username})

    def read(self, token: str) -> dict | None:
        try:
            return self._serializer.loads(token, max_age=self.max_age)
        except SignatureExpired:
            log.debug("session expired")
        except BadSignature:
            log.warning("rejected a session cookie with a bad signature")
        return None


# ---------------------------------------------------------------------- throttling


@dataclass
class _Bucket:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class LoginThrottle:
    """In-memory throttle keyed by client address.

    Deliberately process-local: the panel is a single uvicorn process, and persisting
    lockouts would let an attacker with a spoofable header lock out the real operator.
    """

    max_failures: int = 5
    lockout_seconds: int = 300
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    def check(self, key: str) -> None:
        bucket = self._buckets.get(key)
        if bucket and bucket.locked_until > time.time():
            remaining = int(bucket.locked_until - time.time())
            raise AuthError(f"Too many failed attempts. Try again in {remaining}s.")

    def record_failure(self, key: str) -> None:
        bucket = self._buckets.setdefault(key, _Bucket())
        bucket.failures += 1
        if bucket.failures >= self.max_failures:
            bucket.locked_until = time.time() + self.lockout_seconds
            bucket.failures = 0
            log.warning("locked out %s after repeated failed logins", key)

    def record_success(self, key: str) -> None:
        self._buckets.pop(key, None)
