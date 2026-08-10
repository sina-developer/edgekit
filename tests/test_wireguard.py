"""WireGuard interface status and lifecycle."""

from __future__ import annotations

from edgekit.system import shell
from edgekit.system import wireguard as wg
from edgekit.system.shell import Result


def _ok(argv: tuple[str, ...] | list[str] = ()) -> Result:
    return Result(tuple(argv), 0, "", "")


def _fail(argv: tuple[str, ...] | list[str] = (), code: int = 1) -> Result:
    return Result(tuple(argv), code, "", "failed")


class TestInterfaceUp:
    def test_true_when_interface_exists_even_if_unit_inactive(self, monkeypatch):
        """Dashboard "Up" must follow the live device, not systemd unit state.

        Provision historically called ``wg-quick up`` then only ``systemctl enable``,
        so peers can handshake while ``wg-quick@wg0`` is still inactive.
        """
        monkeypatch.setattr(wg, "interface_exists", lambda iface: iface == "wg0")
        monkeypatch.setattr(shell, "service_active", lambda unit: False)

        assert wg.interface_up("wg0") is True

    def test_false_when_interface_missing(self, monkeypatch):
        monkeypatch.setattr(wg, "interface_exists", lambda iface: False)
        monkeypatch.setattr(shell, "service_active", lambda unit: True)

        assert wg.interface_up("wg0") is False


class TestBringUp:
    def test_starts_via_systemd_when_interface_is_down(self, monkeypatch):
        calls: list[tuple[str, ...]] = []

        monkeypatch.setattr(wg, "interface_exists", lambda iface: False)

        def fake_systemctl(*args: str, check: bool = False) -> Result:
            calls.append(args)
            return _ok(("systemctl", *args))

        monkeypatch.setattr(wg, "systemctl", fake_systemctl)

        def boom_run(*_a, **_k):
            raise AssertionError("bring_up must not shell out to wg-quick directly")

        monkeypatch.setattr(wg, "run", boom_run)

        wg.bring_up("wg0")

        assert ("start", "wg-quick@wg0") in calls

    def test_is_noop_when_interface_already_exists(self, monkeypatch):
        monkeypatch.setattr(wg, "interface_exists", lambda iface: True)

        def boom_systemctl(*_a, **_k):
            raise AssertionError("must not restart an already-up interface")

        monkeypatch.setattr(wg, "systemctl", boom_systemctl)
        wg.bring_up("wg0")
