"""The interactive setup interview.

Answers come from three places, in order of precedence: command-line flags, environment
variables (so the installer can run unattended), then the operator at the prompt. Every
question has a working default, so pressing Enter through the whole thing produces a valid
single-server setup.
"""

from __future__ import annotations

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

from .config import Config
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


def run_wizard(existing: Config | None = None, *, non_interactive: bool = False) -> WizardResult:
    config = existing or Config()

    if not non_interactive:
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
    if not non_interactive:
        _print_cloudflare_checklist(config)
    _collect_certificate(config, non_interactive=non_interactive)

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


def _print_cloudflare_checklist(config: Config) -> None:
    """The three one-time dashboard actions, spelled out with this server's real values.

    These used to be done over the API. They are one-time clicks, so asking the operator to
    do them beats maintaining credentials with enough scope to do them automatically.
    """
    zone = config.cloudflare.zone_name
    ip = config.server.public_ip

    console.print(
        Panel(
            f"""Do these three things in the Cloudflare dashboard for [bold]{zone}[/bold].
Each is one-time — new subdomains later need nothing but a proxy host in edgekit.

[bold]1. DNS[/bold]  (DNS -> Records)  — add two proxied A records:

     Type   Name   Content          Proxy
     A      @      {ip:<15}  Proxied
     A      *      {ip:<15}  Proxied

   The wildcard covers every subdomain you will ever add.

[bold]2. SSL/TLS[/bold]  (SSL/TLS -> Overview) — set the mode to [bold]Full (strict)[/bold].
   Not Flexible: Flexible leaves the Cloudflare-to-server hop unencrypted.

[bold]3. Origin certificate[/bold]  (SSL/TLS -> Origin Server -> Create Certificate)
   Accept the defaults and set the hostnames to:

     *.{zone}
     {zone}

   Cloudflare then shows two boxes, [bold]Origin Certificate[/bold] and [bold]Private Key[/bold].
   The private key is shown once only. Setup will ask you to paste both next; they are
   saved to {ORIGIN_CERT_FILE} and {ORIGIN_KEY_FILE}. One certificate serves every
   subdomain, for 15 years.""",
            title="Cloudflare setup",
            border_style="blue",
        )
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

    if not (cert_path and key_path):
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
        "Origin certificate",
        "supplied" if config.tls.present else "[yellow]none yet[/yellow]",
    )
    if config.public_panel_domain:
        table.add_row("Panel URL", f"https://{config.public_panel_domain}")
    table.add_row("Panel", f"{username}@{config.panel.bind}:{config.panel.port}")
    console.print(Panel(table, title="Summary", border_style="blue"))
