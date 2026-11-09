"""
Host discovery: who is on the LAN, and which MAC answers for which IP.

Strategy (no root/admin, no third-party packages, no child processes):
    1. ARP-sweep the subnet. On Windows, iphlpapi's SendARP resolves each
       address directly. Elsewhere, a one-byte UDP poke makes the kernel ARP
       for each address, and we read the OS ARP cache (`ip neigh` / `arp -an`).
    2. Reverse-DNS each IP for a hostname.

ARP rather than ping: every LAN device must answer ARP to communicate, even
ones whose firewall drops ICMP.

The parsing functions take raw command output as a string so they can be
unit-tested without touching the network.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import oui
from .models import Host

# --- Constants --------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})\b")

logger = logging.getLogger(__name__)


# --- MAC helpers ------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    """'AA-BB-C-DD-EE-FF' -> 'aa:bb:0c:dd:ee:ff'."""
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def is_unicast_mac(mac: str) -> bool:
    """Filter out broadcast/multicast/empty entries that ARP tables include."""
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    first_octet = int(mac.split(":")[0], 16)
    return not first_octet & 0x01  # low bit set => multicast


def is_randomized_mac(mac: str) -> bool:
    """Locally-administered bit set — typical of phones' private Wi-Fi MACs."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def lookup_vendor(mac: str) -> str:
    """Vendor name for display only — never used for detection."""
    if is_randomized_mac(mac):
        return "randomized MAC"
    return oui.lookup(mac)


# --- Parsing ----------------------------------------------------------------
def parse_arp_output(text: str) -> dict[str, str]:
    """Parse `arp -a`, `arp -an` or `ip neigh` output into {ip: mac}.

    All three formats put one IP and one MAC on the same line, so a
    format-agnostic regex is more robust than per-OS column parsing.
    """
    table: dict[str, str] = {}
    for line in text.splitlines():
        if "incomplete" in line.lower() or "failed" in line.lower():
            continue
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not (ip_m and mac_m):
            continue
        ip, mac = ip_m.group(1), normalize_mac(mac_m.group(1))
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or not is_unicast_mac(mac):
            continue
        table[ip] = mac
    return table


def parse_default_gateway(text: str) -> str | None:
    """Pull the default-route gateway out of route-table output.

    Handles:
        Linux   `ip route show default`  -> "default via 192.168.1.1 dev eth0"
        macOS   `route -n get default`   -> "gateway: 192.168.1.1"
        Windows `route print -4 0.0.0.0` -> "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.50  25"
    """
    for line in text.splitlines():
        line = line.strip()
        if m := re.match(r"default via (\S+)", line):
            return m.group(1)
        if m := re.match(r"gateway:\s*(\S+)", line):
            return m.group(1)
        cols = line.split()
        if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
            if IP_RE.fullmatch(cols[2]):
                return cols[2]
    return None


# --- System calls -----------------------------------------------------------
# Never flash a console window for a helper command (matters when NetGuard
# runs windowless, e.g. from the startup task under pythonw).
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, text=True, timeout=10,
                                creationflags=NO_WINDOW)
        return result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("%s failed: %s", cmd[0], exc)
        return ""


def read_arp_table() -> dict[str, str]:
    """Current OS ARP cache as {ip: mac}."""
    if IS_WINDOWS:
        return parse_arp_output(_run(["arp", "-a"]))
    table = parse_arp_output(_run(["ip", "neigh"]))
    return table or parse_arp_output(_run(["arp", "-an"]))


def _windows_gateway() -> str | None:
    """Default gateway via iphlpapi!GetBestRoute: no `route print` process."""
    import ctypes

    class MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulong) for name in (
            "dest", "mask", "policy", "next_hop", "if_index", "type", "proto", "age",
            "next_hop_as", "metric1", "metric2", "metric3", "metric4", "metric5")]

    row = MIB_IPFORWARDROW()
    # Ask "how would you reach a public address?" The answer's next hop is the gateway.
    probe = struct.unpack("<I", socket.inet_aton("1.1.1.1"))[0]
    if ctypes.windll.iphlpapi.GetBestRoute(probe, 0, ctypes.byref(row)) != 0 or not row.next_hop:
        return None
    return socket.inet_ntoa(struct.pack("<I", row.next_hop))


def default_gateway() -> str | None:
    if IS_WINDOWS:
        try:
            if gw := _windows_gateway():
                return gw
        except (OSError, AttributeError):
            pass
        return parse_default_gateway(_run(["route", "print", "-4", "0.0.0.0"]))
    if IS_MAC:
        return parse_default_gateway(_run(["route", "-n", "get", "default"]))
    return parse_default_gateway(_run(["ip", "route", "show", "default"]))


def local_ip(gateway: str | None) -> str | None:
    """This machine's address on the LAN facing `gateway`.

    connect() on a UDP socket only picks a route; no packet is sent.
    """
    if not gateway:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((gateway, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def guess_subnet(gateway: str | None) -> str | None:
    """Assume the common home-network /24 around the gateway."""
    if not gateway:
        return None
    return str(ipaddress.ip_network(f"{gateway}/24", strict=False))


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# --- Sweeping ---------------------------------------------------------------
# The sweep used to launch one `ping` process per address: 254 processes per
# scan, and a visible console window each when running windowless. Both
# strategies below run entirely in-process.

def _send_arp(ip: str) -> str | None:
    """Windows: ask the OS to ARP-resolve `ip` (iphlpapi!SendARP).

    Returns the MAC, or None if nothing answered. Works even for hosts that
    drop ping, since no LAN device can ignore ARP and still talk.
    """
    import ctypes  # Windows-only path; imported lazily

    dest = struct.unpack("<I", socket.inet_aton(ip))[0]
    buf = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    if ctypes.windll.iphlpapi.SendARP(dest, 0, ctypes.byref(buf), ctypes.byref(length)) != 0:
        return None
    if length.value != 6:
        return None
    mac = ":".join(f"{b:02x}" for b in buf[:6])
    return mac if is_unicast_mac(mac) else None


def _udp_poke(ip: str) -> None:
    """Non-Windows: one tiny UDP datagram makes the kernel ARP for `ip`;
    the answer lands in the ARP cache, which we read afterwards."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (ip, 9))  # discard port; nothing listens, nothing breaks
    except OSError:
        pass


def sweep(addresses: list[str], workers: int = 128) -> dict[str, str]:
    """Return {ip: mac} for every address that answered ARP."""
    if IS_WINDOWS:
        # SendARP blocks up to ~3 s on silent addresses but uses no CPU, so
        # plenty of threads keeps a /24 to a few seconds.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return {ip: mac for ip, mac in zip(addresses, pool.map(_send_arp, addresses)) if mac}

    for ip in addresses:
        _udp_poke(ip)
    time.sleep(2.0)  # let ARP replies arrive
    wanted = set(addresses)
    return {ip: mac for ip, mac in read_arp_table().items() if ip in wanted}


# --- Discovery --------------------------------------------------------------
def discover(subnet: str, workers: int = 128) -> list[Host]:
    """Sweep `subnet` and return every host that answered ARP."""
    network = ipaddress.ip_network(subnet, strict=False)
    me = local_ip(str(next(network.hosts(), network.network_address)))
    addresses = [str(ip) for ip in network.hosts() if str(ip) != me]
    logger.info("Sweeping %d addresses in %s ...", len(addresses), network)

    arp = sweep(addresses, workers)

    with ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(arp, pool.map(resolve_hostname, arp)))

    hosts = [Host(mac=mac, ip=ip, hostname=names[ip], vendor=lookup_vendor(mac))
             for ip, mac in arp.items()]
    logger.info("Found %d hosts", len(hosts))
    return hosts
