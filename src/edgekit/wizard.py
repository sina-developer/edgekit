"""The interactive setup interview.

Answers come from three places, in order of precedence: command-line flags, environment
variables (so the installer can run unattended), then the operator at the prompt. Every
question has a working default, so pressing Enter through the whole thing produces a valid
single-server setup.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .config import TLS_MODES, Config
from .paths import ORIGIN_CERT_FILE, ORIGIN_KEY_FILE
from .security import generate_password
from .services.provision import detect_public_ip

console = Console()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


@dataclass
class WizardResult:
    config: Config
    panel_username: str
    panel_password: str
    panel_password_generated: bool
    npm_password_generated: bool


def env(key: str, default: str = "") -> str:
    return os.environ.get(f"EDGEKIT_{key}", default).strip()


def attach_stdin_to_tty(tty_path: str = "/dev/tty") -> bool:
    """Reconnect stdin to the controlling terminal so prompts can wait for input.

    ``curl | sudo bash`` feeds the installer on stdin. By the time ``edgekit setup``
    runs that pipe is at EOF, so the first prompt raises ``EOFError`` and Click
    prints ``Aborted``. Opening ``/dev/tty`` is how sudo itself asks for a password
    in the same situation.

    Returns True if stdin is (now) readable as a terminal or the given path.
    """
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            return True
    except ValueError:
        pass  # stdin is closed
    try:
        new_stdin = open(tty_path, encoding="utf-8")  # noqa: SIM115
    except OSError:
        return False
    sys.stdin = new_stdin
    sys.__stdin__ = new_stdin
    return True


def _ask(
    question: str,
    *,
    default: str = "",
    env_key: str = "",
    password: bool = False,
    validator=None,
    non_interactive: bool = False,
) -> str:
    """Ask once, honouring the environment and falling back to the default when unattended."""
    preset = env(env_key) if env_key else ""
    if preset:
        if validator:
            error = validator(preset)
            if error:
                raise SystemExit(f"EDGEKIT_{env_key} is invalid: {error}")
        return preset
    if non_interactive:
        return default

    while True:
        answer = Prompt.ask(question, default=default, password=password).strip()
        if validator:
            error = validator(answer)
            if error:
                console.print(f"  [red]{error}[/red]")
                continue
        return answer


def _ask_bool(question: str, *, default: bool, env_key: str = "",
              non_interactive: bool = False) -> bool:
    preset = env(env_key) if env_key else ""
    if preset:
        return preset.lower() in ("1", "true", "yes", "y", "on")
    if non_interactive:
        return default
    return Confirm.ask(question, default=default)


# ---------------------------------------------------------------------- validators


def _validate_ip(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "Enter a valid IPv4 address."
    return None


def _validate_subnet(value: str) -> str | None:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        return str(exc)
    if net.version != 4:
        return "Only IPv4 subnets are supported."
    if net.prefixlen > 29:
        return "Use /29 or larger so there is room for peers."
    if not net.is_private:
        return "Use a private range (10/8, 172.16/12 or 192.168/16)."
    return None


def _validate_port(value: str) -> str | None:
    if not value.isdigit() or not 0 < int(value) < 65536:
        return "Enter a port between 1 and 65535."
    return None


def _validate_email(value: str) -> str | None:
    return None if EMAIL_RE.match(value) else "Enter a valid email address."


def _validate_domain(value: str) -> str | None:
    return None if DOMAIN_RE.match(value) else "Enter a domain such as example.com."


def _validate_username(value: str) -> str | None:
    if not re.match(r"^[a-zA-Z0-9._-]{3,32}$", value):
        return "3–32 characters: letters, digits, dot, dash or underscore."
    return None


# ---------------------------------------------------------------------- the interview


def run_wizard(
    existing: Config | None = None,
    *,
    non_interactive: bool = False,
    require_cloudflare: bool = True,
) -> WizardResult:
    config = existing or Config()

    if not non_interactive:
        attach_stdin_to_tty()
        console.print(
            Panel.fit(
                "[bold]edgekit setup[/bold]\n"
                "WireGuard hub + Nginx Proxy Manager on this server.\n"
                "[dim]Press Enter to accept the value in brackets.[/dim]",
                border_style="blue",
            )
        )

    # -- server ---------------------------------------------------------------
    _section("Server")
    detected = config.server.public_ip or detect_public_ip() or ""
    if detected and not non_interactive and not env("PUBLIC_IP"):
        console.print(f"  [dim]Detected public IP: {detected}[/dim]")
    config.server.public_ip = _ask(
        "Public IP of this server",
        default=detected,
        env_key="PUBLIC_IP",
        validator=_validate_ip,
        non_interactive=non_interactive,
    )

    # -- wireguard ------------------------------------------------------------
    _section("WireGuard tunnel")
    config.wireguard.subnet = _ask(
        "Tunnel subnet",
        default=config.wireguard.subnet or "10.50.0.0/24",
        env_key="WG_SUBNET",
        validator=_validate_subnet,
        non_interactive=non_interactive,
    )
    config.wireguard.listen_port = int(
        _ask(
            "WireGuard UDP port",
            default=str(config.wireguard.listen_port or 51820),
            env_key="WG_PORT",
            validator=_validate_port,
            non_interactive=non_interactive,
        )
    )
    if not non_interactive:
        console.print(
            f"  [dim]This hub will be {config.wireguard.hub_address}; "
            f"peers start at {_first_peer_ip(config)}.[/dim]"
        )

    # -- proxy manager --------------------------------------------------------
    _section("Nginx Proxy Manager")
    config.npm.http_port = int(
        _ask("HTTP port", default=str(config.npm.http_port or 80), env_key="NPM_HTTP_PORT",
             validator=_validate_port, non_interactive=non_interactive)
    )
    config.npm.https_port = int(
        _ask("HTTPS port", default=str(config.npm.https_port or 443), env_key="NPM_HTTPS_PORT",
             validator=_validate_port, non_interactive=non_interactive)
    )
    config.npm.admin_port = int(
        _ask("Admin UI port (bound to localhost)", default=str(config.npm.admin_port or 8181),
             env_key="NPM_ADMIN_PORT", validator=_validate_port,
             non_interactive=non_interactive)
    )
    config.npm.admin_email = _ask(
        "Admin email for Nginx Proxy Manager",
        default=config.npm.admin_email or "admin@example.com",
        env_key="NPM_EMAIL",
        validator=_validate_email,
        non_interactive=non_interactive,
    )

    npm_password = env("NPM_PASSWORD") or config.npm.admin_password
    npm_generated = False
    if not npm_password:
        if non_interactive or not Confirm.ask(
            "  Set the NPM admin password yourself?", default=False
        ):
            npm_password = generate_password()
            npm_generated = True
        else:
            npm_password = Prompt.ask("  NPM admin password", password=True)
    config.npm.admin_password = npm_password

    # -- domain and TLS -------------------------------------------------------
    _section("Domain and TLS")
    config.cloudflare.zone_name = _ask(
        "Your domain (root, e.g. example.com)",
        default=config.cloudflare.zone_name,
        env_key="ZONE",
        validator=_validate_domain,
        non_interactive=non_interactive,
    )
    _collect_cloudflare_token(
        config, non_interactive=non_interactive, required=require_cloudflare
    )
    _choose_ssl_mode(config, non_interactive=non_interactive)
    if config.dns_proxied:
        _collect_certificate(config, non_interactive=non_interactive)
    else:
        _ensure_acme_email(config, non_interactive=non_interactive, fresh=existing is None)

    # -- panel ----------------------------------------------------------------
    _section("Management panel")
    config.panel.port = int(
        _ask("Panel port", default=str(config.panel.port or 8088), env_key="PANEL_PORT",
             validator=_validate_port, non_interactive=non_interactive)
    )
    # Bind to the WireGuard hub IP so NPM (Docker) can reverse-proxy the panel at
    # edgekit.<zone>. Override with EDGEKIT_PANEL_BIND=127.0.0.1 for loopback-only.
    # Binding to 0.0.0.0 is never offered: the panel holds every credential on the box.
    bind_override = env("PANEL_BIND")
    if bind_override:
        if bind_override in ("0.0.0.0", "::", "[::]"):
            console.print(
                "  [red]Refusing to bind the panel to all interfaces. "
                "Use the WireGuard hub IP or 127.0.0.1.[/red]"
            )
            raise SystemExit(1)
        config.panel.bind = bind_override
    else:
        config.panel.bind = config.wireguard.hub_ip
    config.panel.public_subdomain = (
        env("PANEL_SUBDOMAIN") or config.panel.public_subdomain or "edgekit"
    )
    if config.cloudflare.zone_name:
        console.print(
            f"  Panel will be published at "
            f"[bold]https://{config.public_panel_domain}[/bold] "
            f"(bound on {config.panel.bind}:{config.panel.port})"
        )

    username = _ask(
        "Panel username",
        default="admin",
        env_key="PANEL_USER",
        validator=_validate_username,
        non_interactive=non_interactive,
    )
    panel_password = env("PANEL_PASSWORD")
    panel_generated = False
    if not panel_password:
        if non_interactive or not Confirm.ask(
            "  Set the panel password yourself?", default=True
        ):
            panel_password = generate_password()
            panel_generated = True
        else:
            while True:
                panel_password = Prompt.ask("  Panel password", password=True)
                if len(panel_password) < 12:
                    console.print("  [red]At least 12 characters.[/red]")
                    continue
                if panel_password == Prompt.ask("  Confirm password", password=True):
                    break
                console.print("  [red]Passwords do not match.[/red]")

    if not non_interactive:
        _summary(config, username)
        if not Confirm.ask("\nProceed with this configuration?", default=True):
            raise SystemExit("Cancelled.")

    return WizardResult(
        config=config,
        panel_username=username,
        panel_password=panel_password,
        panel_password_generated=panel_generated,
        npm_password_generated=npm_generated,
    )


def _print_token_help(zone: str) -> None:
    console.print(
        Panel(
            f"""edgekit keeps Cloudflare in step with the certificate it installs: DNS records
proxied or DNS only, the SSL/TLS mode, and in direct mode the Let's Encrypt DNS challenge.
Browsers are shown a certificate they reject the moment those disagree — for example a
DNS-only record in front of a Cloudflare Origin certificate — so this is required.

Create one at [bold]dash.cloudflare.com/profile/api-tokens[/bold] -> Create Token -> Custom
token, with Zone Resources including [bold]{zone}[/bold]:

  Zone / Zone / Read
  Zone / DNS / Edit
  Zone / Zone Settings / Edit
  Zone / SSL and Certificates / Edit   [dim](optional: lets edgekit issue the origin
                                        certificate instead of you pasting it)[/dim]""",
            title="Cloudflare API token",
            border_style="blue",
        )
    )


async def _verify_cloudflare(token: str, config: Config) -> str:
    """Prove the token can do everything provisioning will ask of it. Returns the zone id."""
    from .services.cloudflare import CloudflareClient

    async with CloudflareClient(token, origin_ca_key=config.cloudflare.origin_ca_key) as client:
        await client.verify_token()
        zone_id = await client.get_zone_id(config.cloudflare.zone_name)
        await client.require_zone_permissions(zone_id)
    return zone_id


def _collect_cloudflare_token(
    config: Config, *, non_interactive: bool, required: bool = True
) -> None:
    """Collect and verify the Cloudflare API token before anything depends on it."""
    import httpx

    from .services.cloudflare import CloudflareError

    cf = config.cloudflare
    cf.origin_ca_key = env("CF_ORIGIN_CA_KEY") or cf.origin_ca_key
    preset = env("CF_TOKEN")
    token = preset or cf.api_token
    if not token:
        if not required:
            return
        if non_interactive:
            raise SystemExit(
                "EDGEKIT_CF_TOKEN is required: edgekit sets DNS proxy status, the SSL mode "
                "and the certificate through the Cloudflare API."
            )
        _print_token_help(cf.zone_name)

    while True:
        if not token:
            token = Prompt.ask("  Cloudflare API token", password=True).strip()
        try:
            zone_id = asyncio.run(_verify_cloudflare(token, config))
        except (CloudflareError, httpx.HTTPError) as exc:
            if preset or non_interactive:
                raise SystemExit(f"The Cloudflare API token was rejected: {exc}") from exc
            console.print(f"  [red]{exc}[/red]")
            token = ""
            continue
        cf.api_token, cf.zone_id, cf.enabled = token, zone_id, True
        console.print(f"  [green]✓[/green] token can manage {cf.zone_name}")
        return


def _choose_ssl_mode(config: Config, *, non_interactive: bool) -> None:
    preset = env("SSL_MODE").lower()
    if preset:
        if preset not in TLS_MODES:
            raise SystemExit(f"EDGEKIT_SSL_MODE must be one of: {', '.join(TLS_MODES)}")
        config.tls.mode = preset
        return
    if non_interactive:
        return

    zone = config.cloudflare.zone_name
    console.print(
        Panel(
            f"""[bold]proxied[/bold]  Visitors -> Cloudflare (orange cloud) -> this server.
  Browsers see Cloudflare's certificate. A Cloudflare Origin certificate secures the hop
  to this server under Full (strict), and this server's IP stays hidden. Needs Cloudflare
  to be able to reach this server on port 443.

[bold]direct[/bold]   Visitors -> this server (DNS only, grey cloud).
  Nginx Proxy Manager obtains a Let's Encrypt certificate for *.{zone} through a
  Cloudflare DNS challenge and renews it itself. Choose this when Cloudflare cannot
  complete TLS with this server — a 525 in proxied mode.

Either way edgekit sets the DNS records, the SSL/TLS mode and the certificate to match.""",
            title="SSL mode",
            border_style="blue",
        )
    )
    config.tls.mode = Prompt.ask("SSL mode", choices=list(TLS_MODES), default=config.tls.mode)


def _validate_acme_email(value: str) -> str | None:
    from .services.certificates import is_placeholder_email

    error = _validate_email(value)
    if error:
        return error
    if is_placeholder_email(value):
        return (
            "Let's Encrypt refuses placeholder addresses. Use a real mailbox — it receives "
            "expiry notices."
        )
    return None


def _ensure_acme_email(config: Config, *, non_interactive: bool, fresh: bool) -> None:
    """Direct mode registers the Let's Encrypt account under the NPM admin email."""
    email = config.npm.admin_email
    if _validate_acme_email(email) is None:
        return
    if not fresh:
        # NPM already has an admin account under this address; changing edgekit's copy here
        # would lock it out of NPM. Provisioning names the fix.
        console.print(
            f"  [yellow]! Let's Encrypt will refuse {email}. Change the admin email inside "
            "NPM, then run `edgekit npm password --email <address>`.[/yellow]"
        )
        return
    if non_interactive:
        raise SystemExit(
            "Direct mode registers the Let's Encrypt account under the NPM admin email, which "
            "cannot be a placeholder: set EDGEKIT_NPM_EMAIL to a real address."
        )
    console.print(
        f"  Let's Encrypt registers the certificate under the NPM admin email, and refuses "
        f"{email}."
    )
    config.npm.admin_email = _ask(
        "Admin email for Nginx Proxy Manager", validator=_validate_acme_email
    )


def _read_pem(path_text: str) -> str:
    path = Path(path_text).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    if path.is_dir():
        raise IsADirectoryError(f"{path} is a directory")
    return path.read_text().strip() + "\n"


def _prompt_pem_paste(label: str) -> str:
    """Read a PEM block from stdin until an END line (or EOF)."""
    console.print(
        f"  Paste the {label} (including the BEGIN/END lines), then press Enter:"
    )
    lines: list[str] = []
    while True:
        line = sys.stdin.readline()
        if line == "":
            break
        stripped = line.rstrip("\r\n")
        if not lines and not stripped.strip():
            continue
        lines.append(stripped)
        if stripped.strip().startswith("-----END "):
            break
    if not lines:
        raise ValueError(f"No {label} was pasted.")
    return "\n".join(lines).strip() + "\n"


def _write_origin_files(certificate: str, key: str) -> None:
    """Persist the pasted pair to the canonical paths for later inspection/reinstall."""
    ORIGIN_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    ORIGIN_CERT_FILE.write_text(certificate)
    ORIGIN_CERT_FILE.chmod(0o644)

    fd = os.open(
        ORIGIN_KEY_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(fd, "w") as fh:
        fh.write(key)


def existing_origin_pair(config: Config) -> tuple[str, str] | None:
    """Return a stored origin cert+key, from config or the files the installer writes."""
    if config.tls.present:
        return config.tls.certificate, config.tls.certificate_key
    try:
        if ORIGIN_CERT_FILE.is_file() and ORIGIN_KEY_FILE.is_file():
            cert = ORIGIN_CERT_FILE.read_text()
            key = ORIGIN_KEY_FILE.read_text()
            if cert.strip() and key.strip():
                return cert, key
    except OSError:
        return None
    return None


def _keep_existing_origin(config: Config, certificate: str, key: str) -> None:
    from .services.certificates import CertificateError, certificate_name, inspect_certificate

    config.tls.certificate = certificate
    config.tls.certificate_key = key
    config.tls.name = certificate_name(config.cloudflare.zone_name)
    try:
        info = inspect_certificate(certificate)
        console.print(
            f"  [green]✓[/green] keeping existing certificate for {', '.join(info.hostnames)}, "
            f"valid until {info.not_after.date()} ({info.days_remaining} days)"
        )
    except CertificateError:
        console.print("  [green]✓[/green] keeping the existing origin certificate")


def _collect_certificate(config: Config, *, non_interactive: bool) -> None:
    """Collect the origin certificate (paste or env paths), validate, and save it."""
    from .services.certificates import (
        CertificateError,
        certificate_name,
        inspect_certificate,
        validate_key_matches,
    )

    cert_path = env("CERT_PATH")
    key_path = env("KEY_PATH")
    existing = None if (cert_path and key_path) else existing_origin_pair(config)
    renewing = False

    if existing and not (cert_path and key_path):
        certificate, key = existing
        info = None
        try:
            validate_key_matches(certificate, key)
            info = inspect_certificate(certificate)
        except (CertificateError, ValueError, OSError):
            info = None

        if non_interactive:
            if info:
                _keep_existing_origin(config, certificate, key)
            return

        console.print()
        if info:
            console.print(
                f"  Found an origin certificate covering {', '.join(info.hostnames)}, "
                f"valid until {info.not_after.date()} ({info.days_remaining} days)."
            )
            if info.expired:
                console.print("  [yellow]It has expired.[/yellow]")
            renew_default = bool(info.expired)
            if not Confirm.ask("Renew the SSL keys (origin certificate)?", default=renew_default):
                _keep_existing_origin(config, certificate, key)
                return
            renewing = True
        else:
            console.print("  Found origin certificate files, but they could not be read.")
            if not Confirm.ask("Replace them with new SSL keys?", default=True):
                return
            renewing = True

    if not (cert_path and key_path) and not renewing:
        if non_interactive:
            return
        console.print()
        if not Confirm.ask(
            "Install the origin certificate now? "
            "(No is fine — you can add it later in the panel)",
            default=True,
        ):
            console.print(
                "  [yellow]Skipped. Until a certificate is installed, Cloudflare will "
                "return 525 while set to Full (strict).[/yellow]\n"
                "  [dim]Add it later with `edgekit cert install --cert FILE --key FILE`, "
                "or paste it in the panel under Settings.[/dim]"
            )
            return

    while True:
        try:
            if cert_path and key_path:
                certificate = _read_pem(cert_path)
                key = _read_pem(key_path)
            else:
                certificate = _prompt_pem_paste("Origin Certificate")
                console.print()
                key = _prompt_pem_paste("Private Key")
            validate_key_matches(certificate, key)
            info = inspect_certificate(certificate)
        except (OSError, CertificateError, ValueError) as exc:
            console.print(f"  [red]{exc}[/red]")
            if non_interactive:
                return
            cert_path = key_path = ""
            if not Confirm.ask("  Try again?", default=True):
                return
            continue

        if info.expired:
            console.print(f"  [red]That certificate expired on {info.not_after.date()}.[/red]")
            if non_interactive:
                return
            cert_path = key_path = ""
            if not Confirm.ask("  Try again?", default=True):
                return
            continue

        saved = False
        try:
            _write_origin_files(certificate, key)
            saved = True
        except OSError as exc:
            console.print(f"  [red]Could not save certificate files: {exc}[/red]")
            if non_interactive:
                return
            if not Confirm.ask("  Continue without saving the files?", default=False):
                cert_path = key_path = ""
                if not Confirm.ask("  Try again?", default=True):
                    return
                continue

        config.tls.certificate = certificate
        config.tls.certificate_key = key
        config.tls.name = certificate_name(config.cloudflare.zone_name)

        console.print(
            f"  [green]✓[/green] certificate for {', '.join(info.hostnames)}, "
            f"valid until {info.not_after.date()} ({info.days_remaining} days)"
        )
        if saved:
            console.print(
                f"  [dim]Saved to {ORIGIN_CERT_FILE} and {ORIGIN_KEY_FILE}[/dim]"
            )
        if config.cloudflare.zone_name and not info.covers(f"test.{config.cloudflare.zone_name}"):
            console.print(
                f"  [yellow]! It does not appear to cover *.{config.cloudflare.zone_name} — "
                "subdomains served through it will fail TLS.[/yellow]"
            )
        return


def _section(title: str) -> None:
    console.print(f"\n[bold]{title}[/bold]")


def _first_peer_ip(config: Config) -> str:
    hosts = config.wireguard.network.hosts()
    next(hosts)
    return str(next(hosts))


def _summary(config: Config, username: str) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_row("Public IP", config.server.public_ip)
    table.add_row("Tunnel", f"{config.wireguard.subnet} (hub {config.wireguard.hub_address})")
    table.add_row("WireGuard port", f"{config.wireguard.listen_port}/udp")
    table.add_row(
        "Proxy ports",
        f"{config.npm.http_port}/tcp, {config.npm.https_port}/tcp, "
        f"admin {config.npm.admin_port} on {config.npm.admin_bind}",
    )
    table.add_row("NPM admin", config.npm.admin_email)
    table.add_row("Domain", config.cloudflare.zone_name or "not set")
    table.add_row(
        "Cloudflare API",
        "token verified" if config.cloudflare.enabled else "[yellow]not configured[/yellow]",
    )
    if config.dns_proxied:
        table.add_row("SSL mode", "proxied — Cloudflare proxy, Origin certificate, Full (strict)")
        table.add_row(
            "Origin certificate",
            "supplied"
            if config.tls.present
            else "[yellow]none — issued through the API if the token allows[/yellow]",
        )
    else:
        table.add_row("SSL mode", "direct — DNS only, Let's Encrypt wildcard")
    if config.public_panel_domain:
        table.add_row("Panel URL", f"https://{config.public_panel_domain}")
    table.add_row("Panel", f"{username}@{config.panel.bind}:{config.panel.port}")
    console.print(Panel(table, title="Summary", border_style="blue"))
