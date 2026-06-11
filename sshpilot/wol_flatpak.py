"""
Flatpak-specific Wake-on-LAN helpers.

Inside the sandbox, raw broadcast sockets, ARP table access, and network-interface
queries are delegated to the host via ``flatpak-spawn --host python3 -c "..."``.
"""

from __future__ import annotations

import base64
import logging
import shutil
import subprocess
from typing import Optional, Tuple

from sshpilot.wol import normalize_mac, validate_mac

logger = logging.getLogger(__name__)

# Host-side inline Python scripts (stdlib-only). Base64-encoded to survive
# shell → flatpak-spawn → python -c quoting.
_WOL_MAGIC_HOST_SCRIPT_B64 = base64.b64encode(r"""
import socket, sys
mac_str = sys.argv[1]
ip = sys.argv[2]
port = int(sys.argv[3])
mac_bytes = bytes(int(b, 16) for b in mac_str.replace('-', ':').lower().split(':'))
packet = b'\xff' * 6 + mac_bytes * 16
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
try:
    sock.settimeout(5)
    sock.sendto(packet, (ip, port))
except Exception as e:
    print(e, file=sys.stderr)
    sys.exit(1)
finally:
    sock.close()
""".strip().encode()).decode()

_BROADCAST_HOST_SCRIPT_B64 = base64.b64encode(r"""
import socket, re, subprocess, sys
target = sys.argv[1]
result = subprocess.run(['ip', '-o', 'route', 'get', target],
                        capture_output=True, text=True)
if result.returncode != 0:
    sys.exit(1)
line = result.stdout.strip()
dev_m = re.search(r'dev\s+(\S+)', line)
if not dev_m:
    sys.exit(1)
dev = dev_m.group(1)
addr = subprocess.run(['ip', '-o', '-4', 'addr', 'show', 'dev', dev],
                      capture_output=True, text=True)
pfx = re.search(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', addr.stdout)
if not pfx:
    sys.exit(1)
ip_addr = pfx.group(1)
prefix_len = int(pfx.group(2))
mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
ip_int = int.from_bytes(socket.inet_aton(ip_addr), 'big')
broadcast_int = (ip_int & mask_int) | (~mask_int & 0xFFFFFFFF)
print(socket.inet_ntoa(broadcast_int.to_bytes(4, 'big')))
""".strip().encode()).decode()

_ARP_HOST_SCRIPT_B64 = base64.b64encode(r"""
import re, socket, subprocess, sys
ip = sys.argv[1]
port = int(sys.argv[2])
trigger = '--no-trigger' not in sys.argv
if trigger:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.close()
    except Exception:
        pass
try:
    with open('/proc/net/arp', 'r') as f:
        for line in f.readlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip and parts[3] != '00:00:00:00:00:00':
                print(parts[3])
                sys.exit(0)
except Exception:
    pass
try:
    out = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
    pat = re.compile(r'\s+\(' + re.escape(ip) + r'\)\s+at\s+([0-9a-fA-F:]{17})', re.I)
    for line in (out.stdout or '').splitlines():
        m = pat.search(line)
        if m:
            mac = m.group(1).strip()
            if mac != '00:00:00:00:00:00':
                print(mac.lower())
                sys.exit(0)
except Exception:
    pass
sys.exit(1)
""".strip().encode()).decode()


def _spawn_host_python(script_b64: str, args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a base64-encoded Python script on the host via ``flatpak-spawn --host``."""
    flatpak_spawn = shutil.which("flatpak-spawn")
    if not flatpak_spawn:
        raise RuntimeError("flatpak-spawn not found")
    cmd = [
        flatpak_spawn, "--host", "python3", "-c",
        f"import base64,sys; exec(base64.b64decode('{script_b64}').decode())",
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _host_script_stdout(
    script_b64: str,
    args: list[str],
    *,
    timeout: int = 10,
    log_label: str = "Host-side script",
) -> Optional[str]:
    """Run a host script and return stripped stdout on success, else None."""
    try:
        proc = _spawn_host_python(script_b64, args, timeout=timeout)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except RuntimeError:
        logger.debug("%s: flatpak-spawn not available", log_label)
    except subprocess.TimeoutExpired:
        logger.debug("%s timed out", log_label)
    except Exception as e:
        logger.debug("%s failed: %s", log_label, e)
    return None


def send_wol(mac: str, broadcast_ip: str, port: int) -> Tuple[bool, str]:
    """Send a WoL magic packet via the host system."""
    try:
        proc = _spawn_host_python(
            _WOL_MAGIC_HOST_SCRIPT_B64,
            [mac, broadcast_ip, str(port)],
            timeout=10,
        )
    except RuntimeError:
        return False, (
            "Wake-on-LAN is not available in Flatpak without flatpak-spawn. "
            "Make sure the Flatpak sandbox has --talk-name=org.freedesktop.Flatpak."
        )
    except subprocess.TimeoutExpired:
        return False, "Host-side WoL timed out."
    except Exception as e:
        logger.warning("WoL (flatpak host) exception: %s", e)
        return False, str(e)
    if proc.returncode == 0:
        logger.info(
            "WoL magic packet sent (flatpak host) for %s to %s:%s",
            mac, broadcast_ip, port,
        )
        return True, "Magic packet sent."
    err = (proc.stderr or "").strip()
    logger.warning("WoL (flatpak host) failed: %s", err)
    return False, err or "Host-side WoL failed."


def get_subnet_broadcast(host_ip: str) -> Optional[str]:
    """Compute the directed broadcast address via the host system."""
    broadcast = _host_script_stdout(
        _BROADCAST_HOST_SCRIPT_B64,
        [host_ip],
        log_label="Host-side broadcast detection",
    )
    if broadcast:
        logger.debug("Host-side broadcast for %s: %s", host_ip, broadcast)
    return broadcast


def get_mac_from_arp(ip: str, port: int, trigger_first: bool) -> Optional[str]:
    """Read the MAC address from the host ARP table."""
    args = [ip, str(port)]
    if not trigger_first:
        args.append("--no-trigger")
    mac = _host_script_stdout(
        _ARP_HOST_SCRIPT_B64,
        args,
        timeout=15,
        log_label="Host-side ARP detection",
    )
    if mac and validate_mac(mac):
        return normalize_mac(mac)
    return None
