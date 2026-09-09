"""Origin certificate issuance and installation into NPM (guide §14, §15)."""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from ..config import Config
from ..models import AuditLog
from .cloudflare import CloudflareClient, certificate_expiry
from .hosts import (
    SETTING_CERT_EXPIRY,
    SETTING_CERT_FINGERPRINT,
    SETTING_CERT_ID,
    SETTING_CERT_NAME,
    get_setting,
    set_setting,
)
from .npm import NPMClient

log = logging.getLogger("edgekit.certificates")


class CertificateError(RuntimeError):
    pass


@dataclass(slots=True)
class CertificateInfo:
    """What a certificate actually covers, so the operator can confirm before installing."""

    subject: str
    issuer: str
    hostnames: list[str]
    not_before: dt.datetime
    not_after: dt.datetime

    @property
    def expired(self) -> bool:
        return self.not_after < dt.datetime.now(dt.timezone.utc)

    @property
    def days_remaining(self) -> int:
        return (self.not_after - dt.datetime.now(dt.timezone.utc)).days

    def covers(self, hostname: str) -> bool:
        """Match a hostname against the certificate's names, honouring one wildcard level."""
        hostname = hostname.lower().rstrip(".")
        for pattern in (h.lower() for h in self.hostnames):
            if pattern == hostname:
                return True
            if pattern.startswith("*.") and "." in hostname:
                if hostname.split(".", 1)[1] == pattern[2:]:
                    return True
        return False


def inspect_certificate(certificate_pem: str) -> CertificateInfo:
    """Parse a PEM certificate, raising a readable error when it is not one."""
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except ValueError as exc:
        raise CertificateError(
            "That does not look like a PEM certificate. It should begin with "
            "'-----BEGIN CERTIFICATE-----'. If you saved the Cloudflare page, make sure you "
            "took the Origin Certificate box and not the Private Key box."
        ) from exc

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        hostnames = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        hostnames = []
    if not hostnames:
        hostnames = [
            attribute.value
            for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]

    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        hostnames=[str(h) for h in hostnames],
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )


def certificate_fingerprint(certificate_pem: str) -> str:
    """SHA-256 over the DER, so PEM whitespace differences do not read as a new certificate."""
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    return cert.fingerprint(hashes.SHA256()).hex()


def validate_key_matches(certificate_pem: str, key_pem: str) -> None:
    """Confirm the private key belongs to the certificate.

    Mismatched pairs are a common copy/paste slip and produce a Cloudflare 525 at the worst
    possible moment — much better to reject them at the point of entry.
    """
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise CertificateError(
            "That does not look like a PEM private key. It should begin with "
            "'-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----'."
        ) from exc

    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except ValueError as exc:
        raise CertificateError("The certificate could not be parsed.") from exc

    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise CertificateError(
            "This private key does not match this certificate. Cloudflare shows both on the "
            "same page when you create an origin certificate — make sure both came from the "
            "same one."
        )


def validate_pair(certificate_pem: str, key_pem: str) -> CertificateInfo:
    """Fatal checks every intake point shares: parseable, matching, and not expired.

    Each of these installs cleanly into NPM and then fails as a Cloudflare 525, which is a
    far harder problem to trace back to the paste that caused it.
    """
    validate_key_matches(certificate_pem, key_pem)
    info = inspect_certificate(certificate_pem)
    if info.expired:
        raise CertificateError(
            f"That certificate expired on {info.not_after.date()}. Cloudflare rejects an "
            "expired origin certificate under Full (strict) — issue a new one."
        )
    return info


def coverage_warnings(info: CertificateInfo, zone_name: str, domains: list[str]) -> list[str]:
    """Non-fatal mismatches between what the certificate covers and what this edge serves.

    Not an error: a single-hostname certificate is a legitimate choice. But installing one
    that covers nothing you serve is almost always a mistake, and it surfaces later as a
    Cloudflare 526 — the handshake succeeds and Cloudflare then refuses a certificate that
    does not name the host it asked for.
    """
    warnings: list[str] = []
    zone_name = (zone_name or "").strip().rstrip(".")
    if zone_name and not info.covers(f"any.{zone_name}"):
        warnings.append(
            f"this certificate does not cover *.{zone_name}, so new subdomains will need "
            "their own certificate"
        )
    uncovered = [d for d in domains if not info.covers(d)]
    if uncovered:
        warnings.append(
            "not covered by this certificate: " + ", ".join(sorted(uncovered))
            + " — Cloudflare will answer 526 for those hostnames"
        )
    return warnings


def certificate_hostnames(zone_name: str) -> list[str]:
    """A wildcard plus the apex covers every subdomain this edge will ever serve.

    That is the point of the guide's §14 note that one certificate is reused by all
    subdomains — new services need DNS and a proxy host, never a new certificate.
    """
    return [f"*.{zone_name}", zone_name]


def certificate_name(zone_name: str) -> str:
    return f"Cloudflare Origin - {zone_name}"


async def issue_and_install(
    session: Session, config: Config, *, actor: str = "system", force: bool = False
) -> dict[str, str]:
    """Issue a Cloudflare Origin certificate and upload it to NPM as a custom certificate.

    Skips issuance when a valid certificate is already installed unless ``force`` is set.
    """
    cf_config = config.cloudflare
    if not (cf_config.enabled and cf_config.api_token and cf_config.zone_name):
        raise RuntimeError("Cloudflare is not configured; cannot issue an origin certificate")

    name = certificate_name(cf_config.zone_name)
    hostnames = certificate_hostnames(cf_config.zone_name)

    if not force:
        existing_id = get_setting(session, SETTING_CERT_ID)
        expiry_raw = get_setting(session, SETTING_CERT_EXPIRY)
        if existing_id and expiry_raw:
            try:
                expires = dt.datetime.fromisoformat(expiry_raw)
            except ValueError:
                expires = None
            if expires and expires > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30):
                log.info("origin certificate valid until %s; skipping issuance", expires.date())
                return {
                    "status": "skipped",
                    "certificate_id": existing_id,
                    "expires": expiry_raw,
                }

    async with CloudflareClient(
        cf_config.api_token, origin_ca_key=cf_config.origin_ca_key
    ) as cf:
        cert = await cf.create_origin_certificate(
            hostnames, validity_days=cf_config.origin_cert_validity_days
        )

    npm_config = config.npm
    async with NPMClient(
        npm_config.api_base, npm_config.admin_email, npm_config.admin_password
    ) as npm:
        cert_id = await npm.upload_custom_certificate(
            name, cert.certificate_pem, cert.private_key_pem
        )

    expires = certificate_expiry(cert.certificate_pem)
    _record(session, cert_id, name, expires, cert.certificate_pem)
    session.add(
        AuditLog(
            actor=actor,
            action="certificate.issue",
            target=name,
            detail=f"hostnames={', '.join(hostnames)} npm_id={cert_id}",
        )
    )
    log.info("installed origin certificate %s as NPM id %s", name, cert_id)

    return {
        "status": "issued",
        "certificate_id": str(cert_id),
        "expires": expires.isoformat() if expires else "",
        "hostnames": ", ".join(hostnames),
    }


def _record(
    session: Session,
    cert_id: int | str,
    name: str,
    expires: dt.datetime | None,
    certificate_pem: str,
) -> None:
    set_setting(session, SETTING_CERT_ID, str(cert_id))
    set_setting(session, SETTING_CERT_NAME, name)
    set_setting(session, SETTING_CERT_EXPIRY, expires.isoformat() if expires else "")
    set_setting(session, SETTING_CERT_FINGERPRINT, certificate_fingerprint(certificate_pem))


async def _already_installed(
    session: Session, npm: NPMClient, certificate_pem: str
) -> str | None:
    """The NPM id already serving this exact certificate, if there is one.

    Re-uploading an unchanged certificate is not free: NPM cannot update one in place, so
    every install creates a record, moves every proxy host onto it, and deletes the old one.
    Doing that on each `edgekit provision` churns the SSL configuration of a working edge for
    no reason, and each cycle is a chance to leave a host pointing at a deleted certificate.
    """
    recorded_id = get_setting(session, SETTING_CERT_ID)
    recorded_print = get_setting(session, SETTING_CERT_FINGERPRINT)
    if not (recorded_id and recorded_print):
        return None
    if recorded_print != certificate_fingerprint(certificate_pem):
        return None
    # NPM's data can be wiped (`edgekit npm reset`) without edgekit hearing about it.
    if not await npm.certificate_exists(int(recorded_id)):
        log.info("recorded certificate %s is gone from NPM; reinstalling", recorded_id)
        return None
    return recorded_id


async def install_manual_certificate(
    session: Session,
    config: Config,
    certificate_pem: str,
    key_pem: str,
    *,
    name: str | None = None,
    actor: str = "system",
    force: bool = False,
) -> dict[str, str]:
    """Install an operator-supplied certificate, for zones not managed via the API.

    Idempotent: installing the certificate that is already installed changes nothing.
    """
    name = name or certificate_name(config.cloudflare.zone_name or config.server.hostname)
    expires = certificate_expiry(certificate_pem)
    npm_config = config.npm
    async with NPMClient(
        npm_config.api_base, npm_config.admin_email, npm_config.admin_password
    ) as npm:
        if not force:
            unchanged = await _already_installed(session, npm, certificate_pem)
            if unchanged:
                log.info("certificate unchanged; keeping NPM id %s", unchanged)
                return {
                    "status": "unchanged",
                    "certificate_id": unchanged,
                    "expires": expires.isoformat() if expires else "",
                }
        cert_id = await npm.upload_custom_certificate(name, certificate_pem, key_pem)

    _record(session, cert_id, name, expires, certificate_pem)
    session.add(AuditLog(actor=actor, action="certificate.install", target=name))
    return {
        "status": "installed",
        "certificate_id": str(cert_id),
        "expires": expires.isoformat() if expires else "",
    }
