"""
Wake-on-LAN support for sshPilot.
Sends magic packets and can detect MAC from local ARP table (host must be on and reachable).
"""

import logging
import re
import socket
import subprocess
import platform
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Optional dependency; send_magic_packet is used only when available
try:
    from wakeonlan import send_magic_packet
    _WOL_AVAILABLE = True
except ImportError:
    _WOL_AVAILABLE = False
    send_magic_packet = None

# MAC: 6 hex bytes, optional separators : or -
_MAC_RE = re.compile(
    r"^(?:(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}){6})$"
)


def is_wol_available() -> bool:
    """Return True if the wakeonlan package is installed."""
    return _WOL_AVAILABLE


def normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase colon-separated (aa:bb:cc:dd:ee:ff)."""
    if not mac or not isinstance(mac, str):
        return ""
    s = mac.strip().replace("-", ":").replace(".", ":")
    if len(s) == 12 and s.isalnum():
        return ":".join(s[i : i + 2] for i in range(0, 12, 2)).lower()
    return s.lower()


def validate_mac(mac: str) -> bool:
    """Return True if the string looks like a valid MAC address."""
    if not mac or not isinstance(mac, str):
        return False
    s = mac.strip().replace("-", ":").replace(".", ":")
    if len(s) == 12 and s.isalnum():
        s = ":".join(s[i : i + 2] for i in range(0, 12, 2))
    return bool(_MAC_RE.match(s))


def send_wol(
    mac: str,
    broadcast_ip: Optional[str] = None,
    port: int = 9,
) -> Tuple[bool, str]:
    """
    Send a Wake-on-LAN magic packet.

    :param mac: MAC address (e.g. aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff).
    :param broadcast_ip: Optional. Default is 255.255.255.255. Use e.g. 192.168.1.255 for subnet.
    :param port: UDP port (default 9).
    :return: (success, message).
    """
    if not _WOL_AVAILABLE:
        return False, "Wake-on-LAN support is not installed (pip install wakeonlan)."
    mac_norm = normalize_mac(mac)
    if not validate_mac(mac_norm):
        return False, "Invalid MAC address."
    try:
        send_magic_packet(
            mac_norm,
            ip_address=broadcast_ip or "255.255.255.255",
            port=port,
        )
        logger.info("WoL magic packet sent for %s to %s:%s", mac_norm, broadcast_ip or "255.255.255.255", port)
        return True, "Magic packet sent."
    except Exception as e:
        logger.warning("WoL send failed: %s", e)
        return False, str(e)


def _resolve_host_to_ip(host: str, port: int = 22) -> Optional[str]:
    """Resolve hostname to an IPv4 address. Returns None on failure."""
    if not host or not host.strip():
        return None
    host = host.strip()
    # If it's already an IPv4 address, return as-is
    try:
        addr = socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        results = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        for _fam, _typ, _proto, _canon, sockaddr in results:
            if sockaddr and len(sockaddr) >= 1:
                return sockaddr[0]
    except Exception as e:
        logger.debug("Resolve %s failed: %s", host, e)
    return None


def _trigger_arp(ip: str, port: int = 22, timeout: float = 2.0) -> None:
    """Trigger ARP by opening a TCP connection to the host so it appears in ARP table."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
    except Exception:
        # Ping-style trigger: some systems might not have SSH open; we still try ARP read
        pass


def _read_arp_linux(ip: str) -> Optional[str]:
    """Read MAC for the given IP from /proc/net/arp. Returns None if not found or invalid."""
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
    except OSError as e:
        logger.debug("Cannot read /proc/net/arp: %s", e)
        return None
    # Header: IP address  HW type  Flags  HW address  Mask  Device
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        arp_ip, _hw_type, _flags, hw_addr = parts[0], parts[1], parts[2], parts[3]
        if arp_ip != ip:
            continue
        if not hw_addr or hw_addr == "00:00:00:00:00:00":
            continue
        if validate_mac(hw_addr):
            return normalize_mac(hw_addr)
    return None


def _read_arp_macos(ip: str) -> Optional[str]:
    """Read MAC for the given IP from 'arp -a' on macOS."""
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("arp -a failed: %s", e)
        return None
    # Lines like: host (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0
    pattern = re.compile(r"\s+\(" + re.escape(ip) + r"\)\s+at\s+([0-9a-fA-F:]+)\s", re.IGNORECASE)
    for line in (out.stdout or "").splitlines():
        m = pattern.search(line)
        if m and validate_mac(m.group(1)):
            return normalize_mac(m.group(1))
    return None


def _read_arp_windows(ip: str) -> Optional[str]:
    """Read MAC for the given IP from 'arp -a' on Windows."""
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("arp -a failed: %s", e)
        return None
    # Windows format: "  192.168.1.50           aa-bb-cc-dd-ee-ff     dynamic"
    for line in (out.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == ip:
            mac = parts[1].replace("-", ":")
            if validate_mac(mac):
                return normalize_mac(mac)
    return None


def get_mac_from_arp(host: str, port: int = 22, trigger_first: bool = True) -> Optional[str]:
    """
    Try to get the MAC address of a host from the local ARP table.

    The host must be on the same subnet and reachable. If trigger_first is True,
    a short TCP connection to the given port is made so the host appears in ARP.

    :param host: Hostname or IP address.
    :param port: Port to connect to to populate ARP (default 22).
    :param trigger_first: If True, try to connect to host:port before reading ARP.
    :return: Normalized MAC address or None if not found.
    """
    ip = _resolve_host_to_ip(host, port)
    if not ip:
        return None
    if trigger_first:
        _trigger_arp(ip, port=port)
    sys = platform.system()
    if sys == "Linux":
        return _read_arp_linux(ip)
    if sys == "Darwin":
        return _read_arp_macos(ip)
    if sys == "Windows":
        return _read_arp_windows(ip)
    # Fallback: try Linux-style path (e.g. some BSDs)
    return _read_arp_linux(ip)
