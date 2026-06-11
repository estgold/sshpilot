"""Tests for Wake-on-LAN module."""

import pytest
from unittest.mock import patch, MagicMock
import socket

from sshpilot.wol import (
    normalize_mac,
    validate_mac,
    send_wol,
    is_wol_available,
    get_subnet_broadcast,
    get_mac_from_arp,
)


def test_normalize_mac():
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("") == ""


def test_validate_mac():
    assert validate_mac("aa:bb:cc:dd:ee:ff") is True
    assert validate_mac("AA-BB-CC-DD-EE-FF") is True
    assert validate_mac("aabbccddeeff") is True
    assert validate_mac("aa:bb:cc:dd:ee:ff:00") is False
    assert validate_mac("gg:bb:cc:dd:ee:ff") is False
    assert validate_mac("") is False
    assert validate_mac("1.2.3.4") is False


def test_send_wol_invalid_mac():
    ok, msg = send_wol("invalid")
    assert ok is False
    assert "Invalid" in msg or "invalid" in msg.lower()


def test_send_wol_empty_mac():
    ok, msg = send_wol("")
    assert ok is False


def test_is_wol_available():
    # Just ensure it returns a bool (True if wakeonlan installed)
    assert isinstance(is_wol_available(), bool)


def test_get_subnet_broadcast_uses_interface_mask():
    """get_subnet_broadcast should use the real interface netmask, not hardcode /24."""
    import psutil
    snic = MagicMock()
    snic.family = socket.AF_INET
    snic.address = "10.0.0.5"
    snic.netmask = "255.255.0.0"  # /16

    with patch("psutil.net_if_addrs", return_value={"eth0": [snic]}):
        result = get_subnet_broadcast("10.0.1.200")
    # With /16 mask the broadcast is 10.0.255.255, not 10.0.1.255
    assert result == "10.0.255.255"


def test_get_subnet_broadcast_slash24():
    """/24 network still works correctly."""
    import psutil
    snic = MagicMock()
    snic.family = socket.AF_INET
    snic.address = "192.168.1.10"
    snic.netmask = "255.255.255.0"

    with patch("psutil.net_if_addrs", return_value={"eth0": [snic]}):
        result = get_subnet_broadcast("192.168.1.50")
    assert result == "192.168.1.255"


def test_get_subnet_broadcast_no_match_returns_none():
    """Returns None when no local interface is on the same subnet as target."""
    import psutil
    snic = MagicMock()
    snic.family = socket.AF_INET
    snic.address = "10.0.0.5"
    snic.netmask = "255.255.255.0"

    with patch("psutil.net_if_addrs", return_value={"eth0": [snic]}):
        result = get_subnet_broadcast("192.168.1.50")
    assert result is None


def test_get_subnet_broadcast_invalid_ip():
    assert get_subnet_broadcast("not-an-ip") is None
    assert get_subnet_broadcast("") is None


# ---------------------------------------------------------------------------
# Flatpak delegation tests
# ---------------------------------------------------------------------------

_MAC_VALID = "aa:bb:cc:dd:ee:ff"
_BROADCAST = "192.168.1.255"
_IP = "192.168.1.50"


@pytest.fixture
def flatpak_env(monkeypatch):
    """Mock is_flatpak() → True and shutil.which('flatpak-spawn') → path."""
    monkeypatch.setattr("sshpilot.wol.is_flatpak", lambda: True)
    monkeypatch.setattr(
        "sshpilot.wol_flatpak.shutil.which",
        lambda cmd: "/usr/bin/flatpak-spawn" if cmd == "flatpak-spawn" else None,
    )
    return monkeypatch


def test_send_wol_flatpak_delegation(flatpak_env):
    """send_wol() in Flatpak delegates to host-side python."""
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=proc) as mock_run:
        ok, msg = send_wol(_MAC_VALID, broadcast_ip=_BROADCAST, port=9)
    assert ok is True
    mock_run.assert_called_once()
    cmd_parts = mock_run.call_args[0][0]
    cmd_str = " ".join(cmd_parts)
    assert "flatpak-spawn" in cmd_str
    assert "--host" in cmd_str
    assert _MAC_VALID in cmd_str
    assert _BROADCAST in cmd_str
    assert "9" in cmd_str


def test_send_wol_flatpak_failure(flatpak_env):
    """send_wol() reports host-side failure."""
    proc = MagicMock(returncode=1, stdout="", stderr="Permission denied")
    with patch("subprocess.run", return_value=proc):
        ok, msg = send_wol(_MAC_VALID, broadcast_ip=_BROADCAST, port=9)
    assert ok is False
    assert "Permission denied" in msg


def test_send_wol_flatpak_no_spawn(flatpak_env, monkeypatch):
    """send_wol() returns error when flatpak-spawn is missing."""
    monkeypatch.setattr("sshpilot.wol_flatpak.shutil.which", lambda cmd: None)
    ok, msg = send_wol(_MAC_VALID, broadcast_ip=_BROADCAST)
    assert ok is False
    assert "flatpak-spawn" in msg.lower()


def test_get_subnet_broadcast_flatpak(flatpak_env):
    """get_subnet_broadcast() in Flatpak delegates to host."""
    proc = MagicMock(returncode=0, stdout=_BROADCAST + "\n", stderr="")
    with patch("subprocess.run", return_value=proc):
        result = get_subnet_broadcast(_IP)
    assert result == _BROADCAST


def test_get_subnet_broadcast_flatpak_failure(flatpak_env):
    """get_subnet_broadcast() returns None on host-side failure."""
    proc = MagicMock(returncode=1, stdout="", stderr="")
    with patch("subprocess.run", return_value=proc):
        result = get_subnet_broadcast(_IP)
    assert result is None


def test_get_mac_from_arp_flatpak(flatpak_env):
    """get_mac_from_arp() in Flatpak delegates to host."""
    proc = MagicMock(returncode=0, stdout=_MAC_VALID + "\n", stderr="")
    with patch("subprocess.run", return_value=proc) as mock_run:
        with patch("sshpilot.wol._resolve_host_to_ip", return_value=_IP):
            result = get_mac_from_arp("test-host")
    assert result == _MAC_VALID
    mock_run.assert_called_once()


def test_get_mac_from_arp_flatpak_no_trigger(flatpak_env):
    """get_mac_from_arp(trigger_first=False) passes --no-trigger to host script."""
    proc = MagicMock(returncode=0, stdout=_MAC_VALID + "\n", stderr="")
    with patch("subprocess.run", return_value=proc) as mock_run:
        with patch("sshpilot.wol._resolve_host_to_ip", return_value=_IP):
            get_mac_from_arp("test-host", trigger_first=False)
    cmd_args = mock_run.call_args[0][0]
    assert "--no-trigger" in cmd_args


def test_arp_host_script_skips_trigger_with_no_trigger_flag():
    """Host ARP script must not TCP-connect when --no-trigger is passed."""
    import base64
    from sshpilot import wol_flatpak

    script = base64.b64decode(wol_flatpak._ARP_HOST_SCRIPT_B64).decode()
    mock_socket = MagicMock()
    with patch("socket.socket", return_value=mock_socket):
        with patch("builtins.open", side_effect=OSError("no arp")):
            with patch("subprocess.run", side_effect=AssertionError("arp -a should not run")):
                with patch("sys.argv", ["_", _IP, "22", "--no-trigger"]):
                    with pytest.raises(SystemExit) as exc:
                        exec(script)
    assert exc.value.code == 1
    mock_socket.assert_not_called()


def test_get_mac_from_arp_flatpak_failure(flatpak_env):
    """get_mac_from_arp() returns None on host-side failure."""
    proc = MagicMock(returncode=1, stdout="", stderr="")
    with patch("subprocess.run", return_value=proc):
        with patch("sshpilot.wol._resolve_host_to_ip", return_value=_IP):
            result = get_mac_from_arp("test-host")
    assert result is None


def test_host_magic_script_sends_packet():
    """The host-side inline script actually constructs and sends a magic packet."""
    import base64
    from sshpilot import wol_flatpak
    script = base64.b64decode(wol_flatpak._WOL_MAGIC_HOST_SCRIPT_B64).decode()
    # Patch sys.argv and socket to verify the packet is correct
    mock_socket = MagicMock()
    with patch("socket.socket", return_value=mock_socket):
        with patch("sys.argv", ["_", _MAC_VALID, _BROADCAST, "9"]):
            try:
                exec(script)
            except SystemExit as e:
                assert e.code == 0
    mock_socket.sendto.assert_called_once()
    packet, dest = mock_socket.sendto.call_args[0]
    mac_bytes = bytes(int(b, 16) for b in normalize_mac(_MAC_VALID).split(":"))
    assert packet == b"\xff" * 6 + mac_bytes * 16
    assert dest == (_BROADCAST, 9)
