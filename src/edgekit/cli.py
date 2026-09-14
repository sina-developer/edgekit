"""Command line interface.

`edgekit setup` is the entry point the installer calls: interview, provision, create the
panel account, install the service. Everything else exists so the same operations are
available without a browser.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import select

from . import __version__, service_unit
from .config import TLS_MODES, Config, load_config
from .db import init_db, session_scope
from .models import ProxyHost, User
from .paths import CONFIG_FILE, LOG_FILE, ensure_dirs
from .security import check_password_strength, generate_password, hash_password
from .services import certificates, health
from .services.hosts import SETTING_CERT_EXPIRY, SETTING_CERT_ID, HostService, get_setting
from .services.peers import PeerError, PeerService
from .services.provision import TLS_STEPS, Provisioner, StepStatus
from .system import firewall
from .system import wireguard as wg
from .system.shell import CommandError, is_root

console = Console()

app = typer.Typer(
    help="WireGuard hub + Nginx Proxy Manager edge server.",
    no_args_is_help=True,
    add_completion=False,
)
peer_app = typer.Typer(help="Manage WireGuard peers.", no_args_is_help=True)
host_app = typer.Typer(help="Manage proxy hosts.", no_args_is_help=True)
cert_app = typer.Typer(help="Manage the origin certificate.", no_args_is_help=True)
user_app = typer.Typer(help="Manage panel accounts.", no_args_is_help=True)
cf_app = typer.Typer(help="Manage the Cloudflare integration.", no_args_is_help=True)
npm_app = typer.Typer(help="Manage Nginx Proxy Manager credentials.", no_args_is_help=True)
ssl_app = typer.Typer(help="Choose and verify how visitors reach this edge.", no_args_is_help=True)
app.add_typer(ssl_app, name="ssl")
app.add_typer(peer_app, name="peer")
app.add_typer(host_app, name="host")
app.add_typer(cert_app, name="cert")
app.add_typer(user_app, name="user")
app.add_typer(cf_app, name="cloudflare")
app.add_typer(npm_app, name="npm")
fw_app = typer.Typer(
    help="Host firewall (ufw): enable, open ports, and check.",
    no_args_is_help=True,
)
app.add_typer(fw_app, name="firewall")


def _for_console(record: logging.LogRecord) -> bool:
    """Records logged with ``extra={"console": False}`` go to the log file only.

    Used for failures a step line has already reported in full: a traceback under it adds
    nothing but a wall of text between the operator and the fix.
    """
    return getattr(record, "console", True)


def setup_logging(verbose: bool = False) -> None:
    ensure_dirs()
    console_handler = RichHandler(
        console=console, show_path=False, rich_tracebacks=True, show_time=False
    )
    console_handler.addFilter(_for_console)
    handlers: list[logging.Handler] = [console_handler]
    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        handlers.append(file_handler)
    except OSError:
        pass  # unprivileged inspection runs still get console output

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=handlers,
        force=True,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)


def require_root() -> None:
    if not is_root():
        console.print("[red]This command needs root. Re-run with sudo.[/red]")
        raise typer.Exit(1)


def require_configured() -> Config:
    config = load_config()
    if not config.configured:
        console.print(
            f"[red]edgekit is not set up yet[/red] (no usable {CONFIG_FILE}).\n"
            "Run [bold]sudo edgekit setup[/bold] first."
        )
        raise typer.Exit(1)
    return config


def _print_version_and_exit(value: bool) -> None:
    if value:
        console.print(f"edgekit {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print version and exit.",
            callback=_print_version_and_exit,
            is_eager=True,
        ),
    ] = False,
) -> None:
    setup_logging(verbose)


@app.command()
def version() -> None:
    """Print the edgekit version."""
    console.print(f"edgekit {__version__}")


# ---------------------------------------------------------------------- setup


@app.command()
def setup(
    non_interactive: Annotated[
        bool, typer.Option("--non-interactive", "-y", help="Accept defaults and environment.")
    ] = False,
    skip_packages: Annotated[
        bool, typer.Option("--skip-packages", help="Assume WireGuard and Docker are installed.")
    ] = False,
    skip_docker: Annotated[
        bool, typer.Option("--skip-docker", help="Do not deploy Nginx Proxy Manager.")
    ] = False,
    skip_cloudflare: Annotated[
        bool, typer.Option("--skip-cloudflare", help="Do not touch Cloudflare.")
    ] = False,
    no_service: Annotated[
        bool, typer.Option("--no-service", help="Do not install the panel systemd unit.")
    ] = False,
) -> None:
    """Interview, provision this server, and start the management panel."""
    require_root()
    ensure_dirs()
    init_db()

    from .wizard import run_wizard

    existing = load_config()
    result = run_wizard(existing if existing.configured else None,
                        non_interactive=non_interactive,
                        require_cloudflare=not skip_cloudflare)
    config = result.config
    config.save()

    console.print()
    report = _run_provisioner(
        config,
        skip_packages=skip_packages,
        skip_docker=skip_docker,
        skip_cloudflare=skip_cloudflare,
    )
    report = _offer_direct_mode(config, report)

    with session_scope() as session:
        existing_user = session.query(User).filter_by(username=result.panel_username).first()
        if existing_user is None:
            session.add(
                User(
                    username=result.panel_username,
                    password_hash=hash_password(result.panel_password),
                    must_change_password=result.panel_password_generated,
                )
            )
            console.print(f"Created panel account [bold]{result.panel_username}[/bold].")
        else:
            console.print(
                f"Panel account [bold]{result.panel_username}[/bold] already exists; "
                "password left unchanged."
            )

    if not no_service:
        service_unit.install()
        console.print("Installed and started [bold]edgekit-panel.service[/bold].")

    _print_setup_summary(config, result, report.ok)
    raise typer.Exit(0 if report.ok else 2)


def _print_step(step) -> None:
    # Newline (not \r) so package/apt sub-logs under a long step stay readable.
    if step.status is StepStatus.RUNNING:
        console.print(f"  [dim]…[/dim] {step.title}")
    elif step.status is StepStatus.DONE:
        console.print(f"  [green]✓[/green] {step.title}"
                      + (f" [dim]— {step.detail}[/dim]" if step.detail else ""))
    elif step.status is StepStatus.SKIPPED:
        console.print(f"  [dim]•[/dim] [dim]{step.title} — skipped "
                      f"({step.detail})[/dim]")
    else:
        console.print(f"  [red]✗[/red] {step.title}\n    [red]{step.detail}[/red]")


def _offer_cloudflare_token(config: Config, *, ask_mode: bool = True) -> None:
    """Installs from before the token was required have none: ask, rather than fail the run.

    Only at a terminal. The panel's update job has nobody to answer, and provisioning then
    names the command to run instead.
    """
    cf = config.cloudflare
    if not cf.zone_name or (cf.enabled and cf.api_token) or not sys.stdin.isatty():
        return
    console.print(
        f"\n[bold]edgekit now manages Cloudflare DNS and the SSL mode for {cf.zone_name}.[/bold]\n"
        "  Keeping them in step with the certificate is what stops browsers being shown one\n"
        "  they reject, and it needs a Cloudflare API token."
    )
    if not typer.confirm("Add the token now?", default=True):
        return

    from .wizard import configure_cloudflare

    configure_cloudflare(config, ask_mode=ask_mode)
    config.save()
    console.print()


def _run_provisioner(config: Config, only: tuple[str, ...] | None = None, **flags) -> object:
    console.print("[bold]Provisioning[/bold]")
    provisioner = Provisioner(config, on_event=_print_step, **flags)
    return asyncio.run(provisioner.run(only))


def _offer_direct_mode(config: Config, report):
    """Cloudflare answered 525: offer the mode that does not route visitors through it.

    TLS on the server can be perfect and still fail here — the network between Cloudflare and
    the server resets the handshake, and no setting on the server changes that. Only at a
    terminal: the switch exposes the server's IP, so it is the operator's call.
    """
    if not (report.cloudflare_525 and config.dns_proxied and sys.stdin.isatty()):
        return report
    console.print(
        "\n[bold yellow]Cloudflare answers 525: its connections to this server fail."
        "[/bold yellow]\n"
        "  When TLS on the server itself passes (`edgekit doctor`), the certificate is not the\n"
        "  cause — the network between Cloudflare and this server is. Direct mode takes\n"
        "  Cloudflare out of the path: DNS only, with a Let's Encrypt certificate served from\n"
        f"  {config.server.public_ip}, so visitors will see that address."
    )
    if not typer.confirm("Switch to direct mode now?", default=True):
        return report
    config.tls.mode = "direct"
    config.save()
    return _run_provisioner(config, only=TLS_STEPS)


def _panel_access_help(config: Config) -> str:
    """How to actually reach the panel, given where it is bound."""
    port = config.panel.port
    user = config.server.ssh_user
    host = config.server.public_ip
    public = config.public_panel_domain

    if public and config.panel.bind not in ("127.0.0.1", "localhost"):
        return (
            f"\n[bold]Opening the panel[/bold]\n"
            f"  Public URL: [bold]https://{public}[/bold]\n"
            f"  Or from a WireGuard peer: [bold]http://{config.panel.bind}:{port}[/bold]\n"
            "  [dim]Keep TCP "
            f"{port} closed on your cloud firewall — only 80/443 and UDP "
            f"{config.wireguard.listen_port} need to be open.[/dim]\n"
        )

    if config.panel.bind in ("127.0.0.1", "localhost"):
        return (
            f"\n[bold]Opening the panel[/bold] (it listens on {config.panel.bind} only)\n"
            "  1. On your own machine, open an SSH tunnel and leave it running:\n"
            f"     [bold]ssh -L {port}:127.0.0.1:{port} {user}@{host}[/bold]\n"
            "     [dim](add -i /path/to/key.pem if you use a key file)[/dim]\n"
            f"  2. Then browse to [bold]http://127.0.0.1:{port}[/bold]\n"
        )

    return (
        f"\n[bold]Opening the panel[/bold] (it listens on {config.panel.bind})\n"
        f"  From any connected WireGuard peer: [bold]http://{config.panel.bind}:{port}[/bold]\n"
        "  Connect a peer first — add one with [bold]edgekit peer add <name>[/bold].\n"
    )


def _print_firewall_ports(config: Config) -> None:
    """Show every cloud-firewall port after install — open vs leave closed."""
    rows = firewall.cloud_firewall_ports(config)
    table = Table(title="Cloud firewall (security group)", title_justify="left")
    table.add_column("Action")
    table.add_column("Proto")
    table.add_column("Port")
    table.add_column("Why")
    for row in rows:
        if row.action == "open":
            action = "[green]OPEN[/green]"
        else:
            action = "[red]KEEP CLOSED[/red]"
        table.add_row(action, row.protocol.upper(), str(row.port), row.purpose)

    console.print()
    console.print(table)
    console.print(
        "  [dim]These rules live at your cloud provider (AWS security group, Hetzner, …), "
        "not in ufw on this host.[/dim]"
    )
    console.print(
        "\n[bold]Next:[/bold] turn on the host firewall and open those ports:\n"
        "  [bold]sudo edgekit firewall setup[/bold]\n"
        "  [bold]sudo edgekit firewall check[/bold]\n"
        "  [dim]ufw covers this VM only. The OPEN ports above still need to be allowed "
        "in the cloud security group.[/dim]"
    )


def _print_setup_summary(config: Config, result, ok: bool) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    if config.public_panel_domain and config.panel.bind not in ("127.0.0.1", "localhost"):
        table.add_row("Panel", f"https://{config.public_panel_domain}")
        table.add_row("Panel bind", f"http://{config.panel.bind}:{config.panel.port}")
    else:
        table.add_row("Panel", f"http://{config.panel.bind}:{config.panel.port}")
    table.add_row("Username", result.panel_username)
    if result.panel_password_generated:
        table.add_row("Password", f"[bold yellow]{result.panel_password}[/bold yellow]")
    if result.npm_password_generated:
        table.add_row("NPM password", f"[bold yellow]{config.npm.admin_password}[/bold yellow]")
    table.add_row("WireGuard", f"{config.server.public_ip}:{config.wireguard.listen_port}/udp")
    table.add_row("Hub key", config.wireguard.public_key)

    console.print()
    console.print(
        Panel(
            table,
            title="[green]Setup complete[/green]"
            if ok
            else "[yellow]Setup finished with errors[/yellow]",
            border_style="green" if ok else "yellow",
        )
    )
    if result.panel_password_generated:
        console.print(
            "[yellow]Save the generated password now — it is not stored in plaintext. "
            "You will be asked to change it at first sign-in.[/yellow]"
        )

    console.print(_panel_access_help(config))
    _print_firewall_ports(config)

    zone = config.cloudflare.zone_name
    if zone and not config.cloudflare.enabled:
        console.print(
            "\n[yellow]No Cloudflare API token is stored, so nothing keeps the DNS records and "
            "SSL mode matched to the certificate.[/yellow]\n"
            f"  [bold]sudo edgekit cloudflare token --zone {zone}[/bold]"
        )

    if not ok:
        console.print("\n[yellow]Run `edgekit doctor` to see what still needs attention.[/yellow]")


@app.command()
def provision(
    skip_packages: bool = typer.Option(False, "--skip-packages"),
    skip_docker: bool = typer.Option(False, "--skip-docker"),
    skip_cloudflare: bool = typer.Option(False, "--skip-cloudflare"),
) -> None:
    """Re-run provisioning. Safe at any time — every step checks before acting."""
    require_root()
    config = require_configured()
    if not skip_cloudflare:
        _offer_cloudflare_token(config)
    report = _run_provisioner(
        config,
        skip_packages=skip_packages,
        skip_docker=skip_docker,
        skip_cloudflare=skip_cloudflare,
    )
    report = _offer_direct_mode(config, report)
    raise typer.Exit(0 if report.ok else 2)


@app.command()
def update(
    repo: Annotated[str, typer.Option("--repo", help="Git URL to fetch.")] = "",
    ref: Annotated[str, typer.Option("--ref", help="Branch or tag to check out.")] = "",
    skip_provision: Annotated[
        bool,
        typer.Option("--skip-provision", help="Reinstall and restart only; do not re-provision."),
    ] = False,
    resume: Annotated[bool, typer.Option("--resume", hidden=True)] = False,
    sha: Annotated[str, typer.Option("--sha", hidden=True)] = "",
) -> None:
    """Fetch the latest edgekit, reinstall, and re-provision. Keeps current settings."""
    require_root()
    config = require_configured()

    if not resume:
        from . import updater

        repo_url = repo or updater.default_repo()
        git_ref = ref or updater.default_ref()
        dest = updater.source_dir()
        console.print(f"Fetching [bold]{repo_url}[/bold] ({git_ref})…")
        try:
            path, identity = updater.resolve_source(repo_url, git_ref, dest)
            console.print(f"Installing [bold]{path}[/bold] ({identity}) into {sys.prefix}")
            updater.install_package(path)
        except (OSError, RuntimeError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc

        new_bin = Path(sys.prefix) / "bin" / "edgekit"
        if not new_bin.is_file():
            console.print(f"[red]pip install succeeded but {new_bin} is missing.[/red]")
            raise typer.Exit(1)
        argv = [str(new_bin), "update", "--resume", "--sha", identity]
        if skip_provision:
            argv.append("--skip-provision")
        # Re-exec so provision and the unit file come from the just-installed package.
        os.execv(str(new_bin), argv)

    console.print(
        f"[green]✓[/green] Installed edgekit {__version__}"
        + (f" ({sha})" if sha else "")
    )
    console.print(f"  Current settings in [bold]{CONFIG_FILE}[/bold] were left unchanged.")

    service_unit.install()
    console.print("Restarted [bold]edgekit-panel.service[/bold].")

    if skip_provision:
        raise typer.Exit(0)

    _offer_cloudflare_token(config)
    report = _offer_direct_mode(config, _run_provisioner(config))
    raise typer.Exit(0 if report.ok else 2)


@app.command()
def uninstall(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
    keep_dns: Annotated[
        bool,
        typer.Option("--keep-dns", help="Leave the DNS records edgekit created in Cloudflare."),
    ] = False,
) -> None:
    """Remove edgekit completely: panel, NPM with its hosts, WireGuard, rules and settings."""
    require_root()
    config = load_config()

    from .uninstall import Uninstaller, describe

    console.print("[bold red]This removes edgekit from this server:[/bold red]")
    for item in describe(config, keep_dns=keep_dns):
        console.print(f"  • {item}")
    console.print(
        "\n[dim]Kept: the Docker and WireGuard packages, ufw with its SSH rule, and DNS "
        "records you created yourself. This cannot be undone.[/dim]"
    )
    if not yes:
        answer = typer.prompt("Type 'remove' to confirm", default="", show_default=False)
        if answer.strip().lower() != "remove":
            console.print("Cancelled; nothing was changed.")
            raise typer.Exit(1)

    console.print("\n[bold]Removing edgekit[/bold]")
    results = asyncio.run(Uninstaller(config, keep_dns=keep_dns, on_event=_print_step).run())
    failed = [r for r in results if r.status is StepStatus.FAILED]
    if failed:
        console.print(
            f"\n[yellow]Finished, but {len(failed)} step(s) failed — what is listed above "
            "under them is still on this server.[/yellow]"
        )
        raise typer.Exit(2)
    console.print("\n[green]✓[/green] edgekit has been removed.")


app.command("remove", hidden=True, help="Alias for uninstall.")(uninstall)


@fw_app.command("setup")
def firewall_setup() -> None:
    """Enable ufw, allow the OPEN ports (SSH first), and print the result."""
    require_root()
    config = require_configured()
    console.print("Allowing SSH first so enabling ufw cannot lock you out.")
    try:
        report = firewall.enable_host_firewall(config)
    except (OSError, RuntimeError, CommandError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    _print_host_firewall_report(report)
    if report.ok:
        console.print(
            "  [dim]Docker was restarted so published 80/443 survive ufw rewriting "
            "iptables.[/dim]"
        )
    raise typer.Exit(0 if report.ok else 1)


@fw_app.command("check")
def firewall_check() -> None:
    """Show whether ufw is on and whether each port matches the expected policy."""
    require_root()
    config = require_configured()
    report = firewall.check_host_firewall(config)
    _print_host_firewall_report(report)
    raise typer.Exit(0 if report.ok else 1)


def _print_host_firewall_report(report: firewall.HostFirewallReport) -> None:
    if not report.installed:
        console.print(
            "[red]ufw is not installed.[/red] Install it with [bold]apt install ufw[/bold]."
        )
        return

    state = "[green]active[/green]" if report.active else "[red]inactive[/red]"
    console.print(f"Host firewall (ufw): {state}")

    table = Table(title="Host firewall ports", title_justify="left")
    table.add_column("Desired")
    table.add_column("Proto")
    table.add_column("Port")
    table.add_column("On this host")
    table.add_column("Why")
    for row in report.ports:
        desired = (
            "[green]OPEN[/green]" if row.action == "open" else "[red]KEEP CLOSED[/red]"
        )
        if row.allowed is True:
            actual = "[green]allowed[/green]"
        elif row.allowed is False:
            actual = "[dim]not allowed[/dim]"
        else:
            actual = "[dim]n/a[/dim]"
        if not row.ok:
            actual = f"[red]fix[/red] ({actual})"
        table.add_row(desired, row.protocol.upper(), str(row.port), actual, row.purpose)
    console.print(table)

    if report.ok:
        console.print("[green]✓[/green] Host firewall matches the expected policy.")
    elif not report.active:
        console.print(
            "[yellow]ufw is off.[/yellow] "
            "Run [bold]sudo edgekit firewall setup[/bold] to enable it."
        )
    else:
        console.print(
            "[yellow]One or more ports are wrong.[/yellow] "
            "Run [bold]sudo edgekit firewall setup[/bold] to apply the policy."
        )
    console.print(
        "  [dim]Cloud security groups are separate — they still need the OPEN ports.[/dim]"
    )


@app.command()
def serve(
    host: str = typer.Option("", help="Override the configured bind address."),
    port: int = typer.Option(0, help="Override the configured port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (development only)."),
) -> None:
    """Run the management panel in the foreground."""
    import uvicorn

    from .web.app import create_app

    config = require_configured()
    init_db()

    bind = host or config.panel.bind
    listen_port = port or config.panel.port
    console.print(f"edgekit panel on http://{bind}:{listen_port}")

    uvicorn.run(
        create_app(config),
        host=bind,
        port=listen_port,
        log_level="info",
        reload=reload,
        access_log=False,
    )


# ---------------------------------------------------------------------- status


@app.command()
def status() -> None:
    """Show a one-screen summary of this edge server."""
    config = require_configured()
    with session_scope() as session:
        service = PeerService(session, config)
        peers = service.list()
        live = service.status_map()
        hosts = HostService(session, config).list()
        cert_expiry = get_setting(session, SETTING_CERT_EXPIRY)

    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_row("Public IP", config.server.public_ip)
    interface_up = wg.interface_up(config.wireguard.interface)
    table.add_row(
        "WireGuard",
        f"[{'green' if interface_up else 'red'}]"
        f"{'up' if interface_up else 'down'}[/] "
        f"{config.wireguard.interface} {config.wireguard.hub_address} "
        f"port {config.wireguard.listen_port}",
    )
    connected = sum(1 for p in peers if (s := live.get(p.public_key)) and s.connected)
    table.add_row("Peers", f"{connected} connected / {len(peers)} registered")
    table.add_row("Proxy hosts", str(len(hosts)))
    table.add_row(
        "Cloudflare",
        config.cloudflare.zone_name if config.cloudflare.enabled else "no API token",
    )
    table.add_row(
        "SSL mode",
        "proxied (Cloudflare proxy + Origin certificate)"
        if config.dns_proxied
        else "direct (DNS only + Let's Encrypt)",
    )
    table.add_row("Certificate", f"expires {cert_expiry[:10]}" if cert_expiry else "none")
    console.print(Panel(table, title="edgekit", border_style="blue"))

    if peers:
        peer_table = Table(title="Peers", title_justify="left")
        peer_table.add_column("Name")
        peer_table.add_column("Address")
        peer_table.add_column("State")
        peer_table.add_column("Handshake")
        for peer in peers:
            state = live.get(peer.public_key)
            if not peer.enabled:
                label = "[dim]disabled[/dim]"
            elif state and state.connected:
                label = "[green]connected[/green]"
            else:
                label = "[red]offline[/red]"
            handshake = "never"
            if state and state.latest_handshake:
                handshake = f"{int(time.time() - state.latest_handshake)}s ago"
            peer_table.add_row(peer.name, peer.address, label, handshake)
        console.print(peer_table)


@app.command()
def doctor() -> None:
    """Run every health check and print what to do about the failures."""
    config = require_configured()
    with session_scope() as session:
        peers = PeerService(session, config).list()
        report = asyncio.run(health.run_all(config, peers))
    report.checks.append(health.cloud_firewall_reminder(config))

    for check in report.checks:
        marker = {
            health.Level.OK: "[green]✓[/green]",
            health.Level.WARN: "[yellow]![/yellow]",
            health.Level.FAIL: "[red]✗[/red]",
            health.Level.SKIP: "[dim]•[/dim]",
        }[check.level]
        console.print(f"{marker} {check.title}"
                      + (f" [dim]— {check.detail}[/dim]" if check.detail else ""))
        if check.remedy:
            console.print(f"    [yellow]{check.remedy}[/yellow]")

    console.print()
    if report.ok:
        console.print("[green]All required checks passed.[/green]")
    else:
        console.print(f"[red]{len(report.failures)} check(s) failed.[/red]")
    raise typer.Exit(0 if report.ok else 1)


# ---------------------------------------------------------------------- peers


@peer_app.command("add")
def peer_add(
    name: str = typer.Argument(..., help="Short name, e.g. raspberry-pi."),
    description: str = typer.Option("", "--description", "-d"),
    address: str = typer.Option("", "--address", help="Tunnel IP; default is the next free."),
    public_key: str = typer.Option("", "--public-key", help="Register a client-generated key."),
    routes: str = typer.Option("", "--routes", help="Extra CIDRs behind this peer."),
    show_config: bool = typer.Option(True, "--show-config/--no-show-config"),
) -> None:
    """Register a peer and print its client configuration."""
    require_root()
    config = require_configured()
    with session_scope() as session:
        service = PeerService(session, config)
        try:
            peer = service.create(
                name,
                description=description,
                address=address or None,
                public_key=public_key or None,
                extra_allowed_ips=routes,
                actor="cli",
            )
            session.flush()
            service.sync()
            rendered = service.render_peer_config(peer) if show_config and not public_key else None
            summary = (peer.name, peer.address, peer.public_key)
        except PeerError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc

    console.print(f"[green]✓[/green] {summary[0]} at {summary[1]}")
    console.print(f"  public key: {summary[2]}")
    if rendered:
        console.print(Panel(rendered, title=f"{summary[0]} — /etc/wireguard/"
                                            f"{config.wireguard.interface}.conf",
                            border_style="blue"))


@peer_app.command("list")
def peer_list() -> None:
    """List registered peers."""
    config = require_configured()
    with session_scope() as session:
        service = PeerService(session, config)
        peers = service.list()
        live = service.status_map()

    table = Table()
    for column in ("ID", "Name", "Address", "Routed", "State", "Public key"):
        table.add_column(column)
    for peer in peers:
        state = live.get(peer.public_key)
        if not peer.enabled:
            label = "[dim]disabled[/dim]"
        elif state and state.connected:
            label = "[green]connected[/green]"
        else:
            label = "[red]offline[/red]"
        table.add_row(
            str(peer.id), peer.name, peer.address, peer.allowed_ips, label,
            peer.public_key[:16] + "…",
        )
    console.print(table if peers else "[dim]No peers registered.[/dim]")


@peer_app.command("show")
def peer_show(name: str) -> None:
    """Print a peer's client configuration."""
    require_root()
    config = require_configured()
    with session_scope() as session:
        service = PeerService(session, config)
        peer = service.get_by_name(name)
        if peer is None:
            console.print(f"[red]No peer named {name!r}.[/red]")
            raise typer.Exit(1)
        try:
            rendered = service.render_peer_config(peer)
        except PeerError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    console.print(rendered)


@peer_app.command("remove")
def peer_remove(
    name: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
) -> None:
    """Remove a peer and re-sync the interface."""
    require_root()
    config = require_configured()
    if not yes and not typer.confirm(f"Delete peer {name!r}?"):
        raise typer.Exit(1)

    with session_scope() as session:
        service = PeerService(session, config)
        peer = service.get_by_name(name)
        if peer is None:
            console.print(f"[red]No peer named {name!r}.[/red]")
            raise typer.Exit(1)
        try:
            service.delete(peer.id, actor="cli")
            session.flush()
            service.sync()
        except PeerError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
    console.print(f"[green]✓[/green] removed {name}")


@peer_app.command("sync")
def peer_sync() -> None:
    """Regenerate wg0.conf from the database and apply it without dropping tunnels."""
    require_root()
    config = require_configured()
    with session_scope() as session:
        PeerService(session, config).sync()
    console.print("[green]✓[/green] interface synchronised")


# ---------------------------------------------------------------------- hosts


@host_app.command("add")
def host_add(
    domain: str = typer.Argument(..., help="Public hostname, e.g. retro.example.com."),
    port: int = typer.Argument(..., help="Port the service listens on."),
    peer: str = typer.Option("", "--peer", help="Peer name to forward to."),
    target: str = typer.Option("", "--target", help="Explicit forward address."),
    scheme: str = typer.Option("http", "--scheme"),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip the Cloudflare record."),
) -> None:
    """Publish a service: DNS record plus NPM proxy host with the origin certificate."""
    require_root()
    config = require_configured()

    async def run() -> str:
        with session_scope() as session:
            service = HostService(session, config)
            peer_id = None
            if peer:
                found = PeerService(session, config).get_by_name(peer)
                if found is None:
                    raise PeerError(f"No peer named {peer!r}")
                peer_id = found.id
            host = await service.create(
                domain=domain,
                forward_port=port,
                peer_id=peer_id,
                forward_host=target or None,
                scheme=scheme,
                manage_dns=not no_dns,
                actor="cli",
            )
            return f"{host.domain} -> {host.target}"

    try:
        console.print(f"[green]✓[/green] {asyncio.run(run())}")
    except Exception as exc:  # noqa: BLE001 - NPM and Cloudflare errors are user-facing
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


@host_app.command("list")
def host_list() -> None:
    """List published proxy hosts."""
    config = require_configured()
    with session_scope() as session:
        hosts = HostService(session, config).list()

    table = Table()
    for column in ("ID", "Domain", "Target", "SSL", "NPM id"):
        table.add_column(column)
    for host in hosts:
        table.add_row(
            str(host.id), host.domain, f"{host.forward_host}:{host.forward_port}",
            "forced" if host.force_ssl else "off", str(host.npm_host_id or "—"),
        )
    console.print(table if hosts else "[dim]No proxy hosts published.[/dim]")


@host_app.command("resync")
def host_resync() -> None:
    """Re-push every proxy host to NPM, e.g. after installing a new certificate."""
    require_root()
    config = require_configured()

    async def run() -> dict[str, str]:
        with session_scope() as session:
            return await HostService(session, config).resync_all()

    outcomes = asyncio.run(run())
    if not outcomes:
        console.print("[dim]No proxy hosts to resync.[/dim]")
        return

    for domain, status_text in outcomes.items():
        marker = "[green]✓[/green]" if status_text == "ok" else "[red]✗[/red]"
        console.print(f"{marker} {domain}" + ("" if status_text == "ok" else f" — {status_text}"))
    if any(s != "ok" for s in outcomes.values()):
        raise typer.Exit(1)


@host_app.command("remove")
def host_remove(
    domain: str,
    remove_dns: bool = typer.Option(False, "--remove-dns"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Remove a proxy host from NPM and from edgekit."""
    require_root()
    config = require_configured()
    if not yes and not typer.confirm(f"Remove {domain}?"):
        raise typer.Exit(1)

    async def run() -> str:
        with session_scope() as session:
            service = HostService(session, config)
            match = next((h for h in service.list() if h.domain == domain), None)
            if match is None:
                raise RuntimeError(f"{domain} is not published")
            return await service.delete(match.id, remove_dns=remove_dns, actor="cli")

    try:
        console.print(f"[green]✓[/green] removed {asyncio.run(run())}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


# ---------------------------------------------------------------------- certificates


@cert_app.command("issue")
def cert_issue(
    force: bool = typer.Option(False, "--force", help="Reissue even if the current one is valid."),
) -> None:
    """Issue a Cloudflare origin certificate and install it into NPM."""
    require_root()
    config = require_configured()

    async def run() -> dict:
        with session_scope() as session:
            return await certificates.issue_and_install(session, config, actor="cli", force=force)

    try:
        outcome = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]✓[/green] certificate {outcome['status']} "
        f"(NPM id {outcome['certificate_id']}, expires {outcome.get('expires', '')[:10]})"
    )


@cert_app.command("install")
def cert_install(
    cert: str = typer.Option(..., "--cert", help="Path to the origin certificate (PEM)."),
    key: str = typer.Option(..., "--key", help="Path to its private key (PEM)."),
    name: str = typer.Option("", "--name", help="Label to show in NPM."),
    force: bool = typer.Option(
        False, "--force", help="Re-upload even when this certificate is already installed."
    ),
) -> None:
    """Install an origin certificate into Nginx Proxy Manager.

    Get one from Cloudflare: SSL/TLS -> Origin Server -> Create Certificate, covering
    `*.yourdomain` and `yourdomain`. It is valid for 15 years and serves every subdomain.
    """
    require_root()
    config = require_configured()

    from pathlib import Path

    from .services.certificates import (
        CertificateError,
        certificate_name,
        coverage_warnings,
        install_manual_certificate,
        validate_pair,
    )

    try:
        certificate_pem = Path(cert).expanduser().read_text().strip() + "\n"
        key_pem = Path(key).expanduser().read_text().strip() + "\n"
        info = validate_pair(certificate_pem, key_pem)
    except (OSError, CertificateError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    label = name or certificate_name(config.cloudflare.zone_name or config.server.hostname)

    async def run() -> tuple[dict, list[str]]:
        with session_scope() as session:
            domains = [h.domain for h in session.scalars(select(ProxyHost))]
            warnings = coverage_warnings(info, config.cloudflare.zone_name, domains)
            outcome = await install_manual_certificate(
                session, config, certificate_pem, key_pem, name=label, actor="cli", force=force
            )
            return outcome, warnings

    try:
        outcome, warnings = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    # Remember it so a rebuilt NPM can be repopulated by `edgekit provision`.
    config.tls.certificate = certificate_pem
    config.tls.certificate_key = key_pem
    config.tls.name = label
    config.save()

    if outcome["status"] == "unchanged":
        console.print(
            f"[green]✓[/green] already installed as NPM id {outcome['certificate_id']} — "
            "nothing changed.\n"
            f"  expires: {info.not_after.date()} ({info.days_remaining} days)\n"
            "  [dim]Re-upload anyway with --force.[/dim]"
        )
    else:
        console.print(
            f"[green]✓[/green] installed as NPM id {outcome['certificate_id']}\n"
            f"  covers:  {', '.join(info.hostnames)}\n"
            f"  expires: {info.not_after.date()} ({info.days_remaining} days)\n"
            "  Existing proxy hosts: run [bold]edgekit host resync[/bold] to attach it."
        )
    for warning in warnings:
        console.print(f"  [yellow]![/yellow] {warning}")


@cert_app.command("status")
def cert_status() -> None:
    """Show the installed certificate."""
    config = require_configured()
    label = "Origin certificate" if config.dns_proxied else "Let's Encrypt certificate"
    with session_scope() as session:
        cert_id = get_setting(session, SETTING_CERT_ID)
        expiry = get_setting(session, SETTING_CERT_EXPIRY)
    if not cert_id:
        console.print(f"[yellow]No {label.lower()} installed ({config.tls.mode} mode).[/yellow]")
        raise typer.Exit(1)
    console.print(
        f"{label} ({config.tls.mode} mode): NPM id {cert_id}, expires {expiry[:10] or 'unknown'}"
    )


# ---------------------------------------------------------------------- ssl


@ssl_app.command("mode")
def ssl_mode(
    mode: Annotated[str, typer.Argument(help="proxied or direct")],
) -> None:
    """Switch how visitors reach this edge, then apply and verify it.

    proxied: Cloudflare proxy in front, Cloudflare Origin certificate, SSL mode Full (strict).
    direct:  DNS only, Let's Encrypt wildcard issued by NPM through a Cloudflare DNS challenge.
    """
    require_root()
    config = require_configured()
    mode = mode.strip().lower()
    if mode not in TLS_MODES:
        console.print(f"[red]Mode must be one of: {', '.join(TLS_MODES)}[/red]")
        raise typer.Exit(1)
    config.tls.mode = mode
    config.save()
    _offer_cloudflare_token(config, ask_mode=False)
    report = _offer_direct_mode(config, _run_provisioner(config, only=TLS_STEPS))
    raise typer.Exit(0 if report.ok else 2)


@ssl_app.command("verify")
def ssl_verify() -> None:
    """Connect to every hostname the way a browser does and report what it is shown."""
    require_root()
    config = require_configured()
    report = _offer_direct_mode(config, _run_provisioner(config, only=("verify_https",)))
    raise typer.Exit(0 if report.ok else 2)


# ---------------------------------------------------------------------- cloudflare


@cf_app.command("token")
def cloudflare_token(
    token: str = typer.Option("", "--token", help="Omit to be prompted without echo."),
    zone: str = typer.Option("", "--zone", help="Root domain, if not already configured."),
    origin_ca_key: str = typer.Option("", "--origin-ca-key"),
) -> None:
    """Store a Cloudflare API token, verifying it before saving."""
    require_root()
    config = require_configured()

    if not token:
        token = typer.prompt("Cloudflare API token", hide_input=True).strip()
    if zone:
        config.cloudflare.zone_name = zone.strip()
    if origin_ca_key:
        config.cloudflare.origin_ca_key = origin_ca_key.strip()
    if not config.cloudflare.zone_name:
        console.print("[red]No zone configured. Pass --zone example.com.[/red]")
        raise typer.Exit(1)

    config.cloudflare.api_token = token
    config.cloudflare.enabled = True

    from .services.cloudflare import CloudflareClient, CloudflareError

    async def verify() -> tuple[str, list]:
        async with CloudflareClient(token, origin_ca_key=config.cloudflare.origin_ca_key) as c:
            await c.verify_token()
            zone_id = await c.get_zone_id(config.cloudflare.zone_name)
            return zone_id, await c.require_zone_permissions(zone_id)

    try:
        config.cloudflare.zone_id, report = asyncio.run(verify())
    except CloudflareError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    config.save()
    console.print(
        f"[green]✓[/green] token stored, zone {config.cloudflare.zone_name} "
        f"= {config.cloudflare.zone_id}"
    )
    for capability in report:
        marker = "[green]✓[/green]" if capability.ok else "[yellow]![/yellow]"
        console.print(f"  {marker} {capability.label} ({capability.permission})")
    console.print("  Run [bold]edgekit provision[/bold] to publish DNS and issue the certificate.")


@cf_app.command("verify")
def cloudflare_verify() -> None:
    """Check the stored Cloudflare token and zone."""
    config = require_configured()
    if not (config.cloudflare.enabled and config.cloudflare.api_token):
        console.print("[yellow]Cloudflare is not configured.[/yellow]")
        raise typer.Exit(1)

    from .services.cloudflare import CloudflareClient, CloudflareError

    async def verify() -> tuple[str, list]:
        async with CloudflareClient(
            config.cloudflare.api_token, origin_ca_key=config.cloudflare.origin_ca_key
        ) as c:
            await c.verify_token()
            zone_id = await c.get_zone_id(config.cloudflare.zone_name)
            return zone_id, await c.check_zone_permissions(zone_id)

    try:
        zone_id, report = asyncio.run(verify())
    except CloudflareError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(f"[green]✓[/green] zone {config.cloudflare.zone_name} = {zone_id}")
    for capability in report:
        marker = "[green]✓[/green]" if capability.ok else "[red]✗[/red]"
        suffix = "" if capability.required else " [dim](optional)[/dim]"
        console.print(f"  {marker} {capability.label} ({capability.permission}){suffix}")
    if any(c.required and not c.ok for c in report):
        raise typer.Exit(1)


# ---------------------------------------------------------------------- npm


@npm_app.command("password")
def npm_password(
    password: str = typer.Option("", "--password", help="Omit to be prompted without echo."),
    email: str = typer.Option("", "--email"),
) -> None:
    """Tell edgekit which credentials Nginx Proxy Manager actually uses.

    This does not change the NPM account — use it when the password was changed inside NPM
    and edgekit's stored copy no longer matches.
    """
    require_root()
    config = require_configured()

    if email:
        config.npm.admin_email = email.strip()
    if not password:
        password = typer.prompt("NPM admin password", hide_input=True).strip()
    config.npm.admin_password = password

    from .services.npm import NPMClient

    async def check() -> str:
        async with NPMClient(
            config.npm.api_base, config.npm.admin_email, config.npm.admin_password
        ) as client:
            user = await client.me()
            return user.get("email", config.npm.admin_email)

    try:
        who = asyncio.run(check())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]NPM rejected those credentials: {exc}[/red]")
        raise typer.Exit(1) from exc

    config.save()
    console.print(f"[green]✓[/green] verified against NPM as {who}")


@npm_app.command("diagnose")
def npm_diagnose() -> None:
    """Report what Nginx Proxy Manager is and which credentials it accepts."""
    require_root()
    config = require_configured()

    from .services.npm import DEFAULT_EMAIL, DEFAULT_PASSWORD, NPMClient
    from .system import dockerx

    state = dockerx.container_state(config.npm.container_name)
    console.print(f"Container: {state.get('status')} ({state.get('image', 'n/a')})")
    console.print(f"API base:  {config.npm.api_base}")

    async def probe() -> tuple[dict, tuple[int, str], tuple[int, str]]:
        async with NPMClient(
            config.npm.api_base, config.npm.admin_email, config.npm.admin_password
        ) as client:
            info = await client.server_info()
            configured = await client.login_probe(
                config.npm.admin_email, config.npm.admin_password
            )
            default = await client.login_probe(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            return info, configured, default

    info, configured, default = asyncio.run(probe())
    console.print(f"Version:   {info.get('version', info) or 'unknown'}")
    console.print(
        f"\nConfigured credentials ({config.npm.admin_email}): "
        f"HTTP {configured[0]}\n  {configured[1]}"
    )
    console.print(
        f"\nShipped defaults ({DEFAULT_EMAIL}): HTTP {default[0]}\n  {default[1]}"
    )

    if configured[0] == 200:
        console.print("\n[green]edgekit's stored credentials work.[/green]")
    elif default[0] == 200:
        console.print(
            "\n[yellow]NPM is still on its default credentials. "
            "Run `edgekit provision` to rotate them.[/yellow]"
        )
    else:
        console.print(
            "\n[red]Neither credential set works.[/red] Open the admin UI to see which "
            "account NPM expects:\n"
            f"  ssh -L {config.npm.admin_port}:127.0.0.1:{config.npm.admin_port} "
            f"{config.server.ssh_user}@{config.server.public_ip}\n"
            f"  then http://127.0.0.1:{config.npm.admin_port}\n"
            "Set the real password with `edgekit npm password`, or start NPM over with "
            "`edgekit npm reset`."
        )


@npm_app.command("reset")
def npm_reset(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Delete Nginx Proxy Manager's data and redeploy it from scratch.

    Destroys every proxy host, certificate and account inside NPM. edgekit's own records
    survive, so `edgekit provision` can repopulate afterwards.
    """
    require_root()
    require_configured()

    from .paths import NPM_DIR
    from .system import dockerx

    data_dirs = [NPM_DIR / "data", NPM_DIR / "letsencrypt"]
    console.print("[bold red]This deletes Nginx Proxy Manager's entire state:[/bold red]")
    for path in data_dirs:
        console.print(f"  {path}{'' if path.exists() else '  [dim](absent)[/dim]'}")
    console.print(
        "\nedgekit's peers and host records are kept, and `edgekit provision` will "
        "recreate the proxy hosts and certificate afterwards."
    )
    if not yes and not typer.confirm("Delete NPM's data and redeploy?"):
        raise typer.Exit(1)

    import shutil

    dockerx.down()
    for path in data_dirs:
        if path.exists():
            shutil.rmtree(path)
            console.print(f"  removed {path}")
    dockerx.up()

    console.print(
        "[green]✓[/green] Nginx Proxy Manager redeployed.\n"
        "  Run [bold]edgekit provision[/bold] to secure the admin account and republish "
        "your hosts."
    )


# ---------------------------------------------------------------------- users


@user_app.command("create")
def user_create(
    username: str,
    password: str = typer.Option("", "--password", help="Omit to generate one."),
) -> None:
    """Create a panel account."""
    require_root()
    require_configured()
    init_db()

    generated = not password
    password = password or generate_password()
    try:
        check_password_strength(password)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    with session_scope() as session:
        if session.query(User).filter_by(username=username).first():
            console.print(f"[red]{username} already exists.[/red]")
            raise typer.Exit(1)
        session.add(
            User(
                username=username,
                password_hash=hash_password(password),
                must_change_password=generated,
            )
        )

    console.print(f"[green]✓[/green] created {username}")
    if generated:
        console.print(f"  password: [bold yellow]{password}[/bold yellow]")


@user_app.command("passwd")
def user_passwd(
    username: str,
    password: str = typer.Option("", "--password", help="Omit to generate one."),
) -> None:
    """Reset a panel account's password."""
    require_root()
    require_configured()

    generated = not password
    password = password or generate_password()
    try:
        check_password_strength(password)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    with session_scope() as session:
        user = session.query(User).filter_by(username=username).first()
        if user is None:
            console.print(f"[red]No account named {username!r}.[/red]")
            raise typer.Exit(1)
        user.password_hash = hash_password(password)
        user.must_change_password = generated

    console.print(f"[green]✓[/green] password updated for {username}")
    if generated:
        console.print(f"  password: [bold yellow]{password}[/bold yellow]")


@user_app.command("list")
def user_list() -> None:
    """List panel accounts."""
    require_configured()
    with session_scope() as session:
        users = session.query(User).order_by(User.username).all()
        rows = [(u.username, u.last_login_at, u.must_change_password) for u in users]

    table = Table()
    for column in ("Username", "Last login", "Must change password"):
        table.add_column(column)
    for username, last_login, must_change in rows:
        table.add_row(
            username,
            last_login.strftime("%Y-%m-%d %H:%M") if last_login else "never",
            "yes" if must_change else "no",
        )
    console.print(table)


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
