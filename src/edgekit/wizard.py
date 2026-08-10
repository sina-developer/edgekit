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
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .config import Config
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

    # -- cloudflare -----------------------------------------------------------
    _section("Cloudflare")
    config.cloudflare.enabled = _ask_bool(
        "Manage DNS, SSL mode and origin certificates through the Cloudflare API?",
        default=config.cloudflare.enabled or bool(env("CF_TOKEN")),
        env_key="CF_ENABLED",
        non_interactive=non_interactive,
    )
    if config.cloudflare.enabled:
        config.cloudflare.zone_name = _ask(
            "Zone (root domain)",
            default=config.cloudflare.zone_name,
            env_key="CF_ZONE",
            validator=_validate_domain,
            non_interactive=non_interactive,
        )
        if not non_interactive and not env("CF_TOKEN"):
            console.print(
                "  [dim]Token needs: Zone:Read, DNS:Edit, Zone Settings:Edit, "
                "SSL and Certificates:Edit.[/dim]"
            )
        config.cloudflare.api_token = _ask(
            "Cloudflare API token",
            default=config.cloudflare.api_token,
            env_key="CF_TOKEN",
            password=True,
            non_interactive=non_interactive,
        )
        config.cloudflare.origin_ca_key = _ask(
            "Origin CA key (optional, press Enter to skip)",
            default=config.cloudflare.origin_ca_key,
            env_key="CF_ORIGIN_CA_KEY",
            password=True,
            non_interactive=non_interactive,
        )
        config.cloudflare.proxied = _ask_bool(
            "Proxy DNS records through Cloudflare (orange cloud)?",
            default=True,
            env_key="CF_PROXIED",
            non_interactive=non_interactive,
        )

    # -- panel ----------------------------------------------------------------
    _section("Management panel")
    config.panel.port = int(
        _ask("Panel port", default=str(config.panel.port or 8088), env_key="PANEL_PORT",
             validator=_validate_port, non_interactive=non_interactive)
    )
    expose = _ask_bool(
        "Expose the panel on the WireGuard address as well as localhost?",
        default=False,
        env_key="PANEL_EXPOSE_WG",
        non_interactive=non_interactive,
    )
    # Binding to 0.0.0.0 is never offered: the panel holds every credential on the box.
    config.panel.bind = config.wireguard.hub_ip if expose else "127.0.0.1"

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
    table.add_row(
        "Cloudflare",
        f"{config.cloudflare.zone_name} (SSL {config.cloudflare.ssl_mode})"
        if config.cloudflare.enabled
        else "disabled",
    )
    table.add_row("Panel", f"{username}@{config.panel.bind}:{config.panel.port}")
    console.print(Panel(table, title="Summary", border_style="blue"))
