"""
Optional live packet capture: port scans, ARP spoofing and rogue DHCP.

This is the only part of NetGuard that needs extras:
    * `pip install scapy`
    * admin/root privileges (raw capture)
    * on Windows, Npcap (https://npcap.com)

Everything else works with the standard library alone, so scapy is imported
lazily and its absence just disables these features.

Packet parsing is split from the detectors (in detect.py) so the detection
logic is testable with plain function calls.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import logging
import random
import threading
from dataclasses import dataclass
from typing import Callable

from .detect import ArpWatcher, DhcpWatcher, PortScanDetector
from .models import Alert

logger = logging.getLogger(__name__)

SYN, ACK = 0x02, 0x10
DHCP_OFFER, DHCP_ACK = 2, 5
BPF_FILTER = "tcp or arp or (udp and (port 67 or port 68))"


@dataclass
class Watchers:
    """Which detectors the sniffer should feed. Any can be None."""

    port_scan: PortScanDetector | None = None
    arp: ArpWatcher | None = None
    dhcp: DhcpWatcher | None = None


# --- Functions --------------------------------------------------------------
def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False
    return True


def dhcp_options(pkt) -> dict:
    """scapy's DHCP options list -> dict (skipping 'end'/'pad' markers)."""
    from scapy.all import DHCP
    return {opt[0]: opt[1] for opt in pkt[DHCP].options
            if isinstance(opt, tuple) and len(opt) >= 2}


def make_handler(watchers: Watchers, on_alert: Callable[[Alert], None],
                 local_ips: set[str]) -> Callable:
    from scapy.all import ARP, BOOTP, DHCP, IP, TCP, Ether

    def handle(pkt) -> None:
        ts = float(pkt.time)
        alert = None

        if watchers.arp and ARP in pkt:
            # Both requests and replies assert "psrc is at hwsrc".
            a = pkt[ARP]
            alert = watchers.arp.feed(a.psrc, a.hwsrc.lower(), ts)

        elif watchers.dhcp and DHCP in pkt:
            opts = dhcp_options(pkt)
            if opts.get("message-type") in (DHCP_OFFER, DHCP_ACK):
                server = opts.get("server_id") or pkt[IP].src
                mac = pkt[Ether].src.lower() if Ether in pkt else ""
                alert = watchers.dhcp.feed(str(server), mac, pkt[BOOTP].yiaddr, ts)

        elif watchers.port_scan and IP in pkt and TCP in pkt:
            flags = int(pkt[TCP].flags)
            # Initial SYN only (no ACK): one per connection attempt.
            if flags & SYN and not flags & ACK:
                if not local_ips or pkt[IP].dst in local_ips:
                    alert = watchers.port_scan.feed(pkt[IP].src, int(pkt[TCP].dport), ts)

        if alert:
            on_alert(alert)

    return handle


def start_sniffer(on_alert: Callable[[Alert], None], local_ips: set[str],
                  watchers: Watchers, iface: str | None = None) -> threading.Event:
    """Sniff in a daemon thread. Returns an Event that stops it.

    `on_alert` is called from the sniffer thread, so it must be thread-safe
    (the monitor passes `queue.Queue.put`).
    """
    from scapy.all import sniff  # optional dependency

    handle = make_handler(watchers, on_alert, local_ips)
    stop = threading.Event()

    def run() -> None:
        try:
            sniff(filter=BPF_FILTER, prn=handle, store=False, iface=iface,
                  stop_filter=lambda _: stop.is_set())
        except Exception as exc:  # permissions, missing Npcap, bad iface...
            logger.error("Sniffer stopped: %s (run as admin; Windows needs Npcap)", exc)

    threading.Thread(target=run, name="netguard-sniffer", daemon=True).start()
    enabled = [n for n in ("port_scan", "arp", "dhcp") if getattr(watchers, n)]
    logger.info("Sniffer running (%s)", ", ".join(enabled))
    return stop


def probe_dhcp_servers(timeout: float = 5.0, iface: str | None = None) -> list[dict]:
    """Broadcast one DHCPDISCOVER and list every server that answers.

    Never sends a REQUEST, so no lease is taken. Normally exactly one server
    should reply; two or more means a rogue (or misconfigured) DHCP server.
    """
    from scapy.all import (BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr,
                           srp)

    iface = iface or conf.iface
    mac = get_if_hwaddr(iface)
    xid = random.randint(1, 0xFFFFFFFF)
    discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    conf.checkIPaddr = False  # offers come from the server's IP, not 255.255.255.255
    answered, _ = srp(discover, iface=iface, multi=True, timeout=timeout, verbose=False)

    servers: dict[str, dict] = {}
    for _, reply in answered:
        if DHCP not in reply or reply[BOOTP].xid != xid:
            continue
        opts = dhcp_options(reply)
        server = str(opts.get("server_id") or reply[IP].src)
        servers[server] = {
            "server_ip": server, "server_mac": reply[Ether].src.lower(),
            "offered_ip": reply[BOOTP].yiaddr, "router": str(opts.get("router", "")),
            "dns": str(opts.get("name_server", "")),
        }
    return list(servers.values())
