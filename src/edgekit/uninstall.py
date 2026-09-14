"""Remove edgekit from this server: everything it created, and nothing it did not.

`edgekit uninstall` and the panel's Remove button both land here. Every step is attempted even
when an earlier one fails — a removal that stops half way leaves a server that is neither
working nor clean — and each reports what it did, so the operator knows exactly what is left.

Deliberately kept: the Docker and WireGuard packages, which other software may use; ufw, its
SSH rule and its forward policy, whose removal can lock the operator out; and DNS records
edgekit did not create.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .config import Config
from .paths import (
    CONFIG_DIR,
    LOG_DIR,
    NPM_DIR,
    ORIGIN_CERT_FILE,
    ORIGIN_KEY_FILE,
    PANEL_UNIT,
    PROGRAM_DIR,
    PROGRAM_LINK,
    STATE_DIR,
    SYSCTL_FILE,
)
from .services.provision import SkipStep, StepResult, StepStatus
from .system import dockerx, firewall
from .system import wireguard as wg
from .system.shell import has, run, systemctl

log = logging.getLogger("edgekit.uninstall")

EventCallback = Callable[[StepResult], None] | None


def owns_program() -> bool:
    """Whether the running edgekit is the installer's copy — never delete a developer checkout."""
    try:
        return Path(sys.prefix).resolve().is_relative_to(PROGRAM_DIR.resolve())
    except OSError:
        return False


def describe(config: Config, *, keep_dns: bool = False) -> list[str]:
    """What removal deletes, in words, for the confirmation prompt."""
    cf = config.cloudflare
    items = [
        "the edgekit panel service and every panel account",
        f"Nginx Proxy Manager ({NPM_DIR}): every proxy host, certificate and login in it",
        f"the WireGuard interface {config.wireguard.interface} and its keys — every peer is "
        "disconnected",
        "edgekit's iptables and ufw rules, systemd units and sysctl settings",
        f"settings, credentials and records ({CONFIG_DIR}, {STATE_DIR}) and logs ({LOG_DIR})",
        f"the saved origin certificate and key ({ORIGIN_CERT_FILE}, {ORIGIN_KEY_FILE})",
    ]
    if cf.api_token and cf.zone_id and not keep_dns:
        items.insert(2, f"the DNS records edgekit created in {cf.zone_name}")
    if owns_program():
        items.append(f"edgekit itself ({PROGRAM_DIR}, {PROGRAM_LINK})")
    return items


def _remove_path(path: Path) -> bool:
    """Delete a file, symlink or directory tree. Returns whether anything was there."""
    if path.is_symlink() or path.is_file():
        path.unlink()
        return True
    if not path.is_dir():
        return False
    if len(path.resolve().parts) < 3:
        raise RuntimeError(f"refusing to delete {path}")
    shutil.rmtree(path)
    return True


class Uninstaller:
    def __init__(
        self, config: Config, *, keep_dns: bool = False, on_event: EventCallback = None
    ) -> None:
        self.config = config
        self.keep_dns = keep_dns
        self.on_event = on_event

    def _emit(self, result: StepResult) -> None:
        if self.on_event:
            try:
                self.on_event(result)
            except Exception:  # noqa: BLE001 - a broken listener must not stop removal
                log.exception("uninstall event listener raised")

    async def _step(
        self, key: str, title: str, fn: Callable[[], Any | Awaitable[Any]]
    ) -> StepResult:
        self._emit(StepResult(key, title, StepStatus.RUNNING))
        try:
            outcome = fn()
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
        except SkipStep as skip:
            result = StepResult(key, title, StepStatus.SKIPPED, str(skip))
        except Exception as exc:  # noqa: BLE001 - reported, and the next step still runs
            log.exception("uninstall step %s failed", key)
            result = StepResult(key, title, StepStatus.FAILED, str(exc))
        else:
            result = StepResult(key, title, StepStatus.DONE, str(outcome or ""))
        self._emit(result)
        return result

    async def run(self) -> list[StepResult]:
        steps: list[tuple[str, str, Callable[[], Any]]] = [
            ("panel", "Stop and remove the panel service", self.step_panel),
            ("dns", "Delete edgekit's DNS records", self.step_dns),
            ("firewall", "Remove firewall rules and units", self.step_firewall),
            ("npm", "Remove Nginx Proxy Manager and its data", self.step_npm),
            ("wireguard", "Remove the WireGuard interface and keys", self.step_wireguard),
            ("sysctl", "Remove sysctl settings", self.step_sysctl),
            ("files", "Delete settings, credentials and records", self.step_files),
            ("program", "Remove edgekit itself", self.step_program),
        ]
        return [await self._step(key, title, fn) for key, title, fn in steps]

    # ---------------------------------------------------------------- steps

    def step_panel(self) -> str:
        from . import service_unit

        if not PANEL_UNIT.exists():
            raise SkipStep("not installed")
        service_unit.uninstall()
        return "stopped, disabled and deleted"

    async def step_dns(self) -> str:
        cf = self.config.cloudflare
        if self.keep_dns:
            raise SkipStep("--keep-dns")
        if not (cf.api_token and cf.zone_id):
            raise SkipStep("no Cloudflare API token stored")

        from .services.cloudflare import CloudflareClient

        async with CloudflareClient(cf.api_token, origin_ca_key=cf.origin_ca_key) as client:
            records = await client.managed_records(cf.zone_id)
            for record in records:
                await client.delete_dns_record(cf.zone_id, record["id"])
        if not records:
            return "none found"
        return "deleted " + ", ".join(sorted(r.get("name", r["id"]) for r in records))

    def step_firewall(self) -> str:
        removed = firewall.remove_edgekit_rules(self.config)
        return "; ".join(removed) if removed else "nothing to remove"

    def step_npm(self) -> str:
        if not NPM_DIR.exists():
            raise SkipStep(f"{NPM_DIR} absent")
        if has("docker") and dockerx.COMPOSE_FILE.exists():
            dockerx.compose(
                "down", "--volumes", "--remove-orphans", "--rmi", "all", check=False
            )
        _remove_path(NPM_DIR)
        return f"containers and image removed, {NPM_DIR} deleted"

    def step_wireguard(self) -> str:
        interface = self.config.wireguard.interface
        path = wg.config_path(interface)
        if not path.exists() and not wg.interface_exists(interface):
            raise SkipStep("not configured")
        try:
            wg.bring_down(interface)
        finally:
            systemctl("disable", f"wg-quick@{interface}")
            path.unlink(missing_ok=True)
        return f"{interface} down and disabled, {path} deleted"

    def step_sysctl(self) -> str:
        if not SYSCTL_FILE.exists():
            raise SkipStep("absent")
        SYSCTL_FILE.unlink()
        run(["sysctl", "--system"])
        # Not switched off live: Docker needs forwarding too, and it goes with the next boot.
        return f"{SYSCTL_FILE} deleted"

    def step_files(self) -> str:
        paths = (CONFIG_DIR, STATE_DIR, LOG_DIR, ORIGIN_CERT_FILE, ORIGIN_KEY_FILE)
        removed = [str(path) for path in paths if _remove_path(path)]
        return f"deleted {', '.join(removed)}" if removed else "nothing left"

    def step_program(self) -> str:
        if not owns_program():
            raise SkipStep(f"this edgekit does not run from {PROGRAM_DIR}")
        _remove_path(PROGRAM_LINK)
        _remove_path(PROGRAM_DIR)
        return f"{PROGRAM_DIR} and {PROGRAM_LINK} deleted"
