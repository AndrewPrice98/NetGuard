"""
TCP connect scan of a small, fixed list of interesting ports.

This is used only to fingerprint devices on *your own* LAN so NetGuard can
notice when one of them starts exposing something new. A plain connect()
needs no admin rights and no raw sockets.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .models import PortState

# --- Constants --------------------------------------------------------------
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 548: "afp", 554: "rtsp", 1883: "mqtt", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5000: "upnp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9100: "printer", 27017: "mongodb",
}

# Ports whose sudden appearance is a strong sign of remote access or a
# backdoor rather than a normal app update.
RISKY_PORTS = {22, 23, 135, 139, 445, 3389, 4444, 5900, 6379, 27017}

CONNECT_TIMEOUT = 0.5


# --- Functions --------------------------------------------------------------
def is_open(ip: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def scan_host(mac: str, ip: str, ports: dict[int, str] | None = None,
              workers: int = 32) -> list[PortState]:
    """Return the open ports on one host."""
    ports = ports or COMMON_PORTS
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, is_open(ip, p)), ports)
        return [PortState(mac=mac, port=p, service=ports[p])
                for p, up in results if up]
