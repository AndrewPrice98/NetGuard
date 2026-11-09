"""
Offline packet-capture analysis: run NetGuard's live detectors over a
.pcap / .pcapng file. Standard library only, no scapy or Wireshark needed.

This is the forensic workflow: someone hands you a capture from the time
of an incident, and you want to know whether it contains ARP poisoning, a
rogue DHCP server or a port scan, and *which frame* shows it so you can open
exactly that packet in Wireshark.

    netguard pcap capture.pcapng
    netguard pcap capture.pcap --gateway 192.168.1.1 --import

The same three detectors (detect.ArpWatcher, DhcpWatcher, PortScanDetector)
run live in sniffer.py; both paths decode packets into the small event
types below and hand them to `dispatch()`, so live and offline detection
cannot drift apart.

Supported: classic libpcap (both byte orders, micro- and nanosecond) and
pcapng (SHB/IDB/EPB/SPB blocks); Ethernet (with 802.1Q/802.1ad tags) and
Linux cooked capture (SLL) link types; IPv4 ARP, TCP, UDP/DHCP.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import ipaddress
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .detect import ArpWatcher, DhcpWatcher, PortScanDetector
from .models import Alert

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
ETH_IPV4, ETH_ARP, ETH_VLAN, ETH_QINQ = 0x0800, 0x0806, 0x8100, 0x88A8
TCP_SYN, TCP_ACK = 0x02, 0x10
DHCP_OFFER, DHCP_ACK = 2, 5
DHCP_MAGIC = b"\x63\x82\x53\x63"


class CaptureError(ValueError):
    """The file isn't a capture we can read."""


# --- Decoded events ---------------------------------------------------------
@dataclass(frozen=True)
class ArpClaim:
    """Every ARP packet asserts "ip is at mac" (requests and replies alike)."""
    ip: str
    mac: str


@dataclass(frozen=True)
class TcpSyn:
    """An initial SYN (no ACK): one connection attempt."""
    src: str
    dst: str
    dport: int


@dataclass(frozen=True)
class DhcpReply:
    """A DHCP OFFER or ACK: proof that `server_ip` is acting as a DHCP server."""
    server_ip: str
    server_mac: str
    offered_ip: str
    router: str = ""
    dns: str = ""


Event = ArpClaim | TcpSyn | DhcpReply


@dataclass
class Watchers:
    """Which detectors to feed. Any can be None."""
    port_scan: PortScanDetector | None = None
    arp: ArpWatcher | None = None
    dhcp: DhcpWatcher | None = None


def dispatch(event: Event, ts: float, watchers: Watchers,
             local_ips: set[str] | frozenset = frozenset()) -> Alert | None:
    """Feed one decoded event to the matching detector. Shared by the live
    sniffer and offline analysis."""
    if isinstance(event, ArpClaim) and watchers.arp:
        return watchers.arp.feed(event.ip, event.mac, ts)
    if isinstance(event, DhcpReply) and watchers.dhcp:
        return watchers.dhcp.feed(event.server_ip, event.server_mac, event.offered_ip, ts)
    if isinstance(event, TcpSyn) and watchers.port_scan:
        if not local_ips or event.dst in local_ips:
            return watchers.port_scan.feed(event.src, event.dport, ts)
    return None


# --- Reading capture files --------------------------------------------------
def read_capture(path: Path | str) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame bytes) for every packet."""
    with open(path, "rb") as f:
        data = f.read()
    yield from parse_capture(data)


def parse_capture(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    if len(data) < 24:
        raise CaptureError("File too short to be a packet capture")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
        return
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if magic not in formats:
        raise CaptureError("Not a pcap or pcapng file (unknown magic number)")
    endian, unit = formats[magic]
    linktype = struct.unpack_from(endian + "I", data, 20)[0] & 0x0FFFFFFF
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + incl > len(data):
            break  # truncated final record
        yield sec + frac * unit, linktype, data[off:off + incl]
        off += incl


def _pcapng(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    off, endian = 0, "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    while off + 12 <= len(data):
        if data[off:off + 4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, hi, lo, caplen, _ = struct.unpack_from(endian + "IIIII", body, 0)
            if iface < len(interfaces):
                linktype, tick = interfaces[iface]
                yield ((hi << 32) | lo) * tick, linktype, body[20:20 + caplen]
        elif btype == 3 and interfaces:  # Simple Packet Block (no timestamp)
            yield 0.0, interfaces[0][0], body[4:]
        off += blen


def _tsresol(options: bytes, endian: str) -> float:
    """if_tsresol option (code 9); default microseconds."""
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, off)
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[off + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        off += 4 + (length + 3) // 4 * 4
    return 1e-6


# --- Decoding frames --------------------------------------------------------
def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


@dataclass
class Frame:
    """What one frame told us: the sender's MAC/IP and at most one event."""
    src_mac: str = ""
    src_ip: str = ""
    proto: str = "other"
    event: Event | None = None


def decode(linktype: int, frame: bytes) -> Frame:
    """Decode a link-layer frame. Never raises on malformed input."""
    try:
        return _decode(linktype, frame)
    except (struct.error, IndexError, ValueError):
        return Frame(proto="malformed")


def _decode(linktype: int, frame: bytes) -> Frame:
    if linktype == LINKTYPE_ETHERNET:
        src_mac = _mac(frame[6:12])
        etype, off = struct.unpack_from("!H", frame, 12)[0], 14
        while etype in (ETH_VLAN, ETH_QINQ):
            etype, off = struct.unpack_from("!H", frame, off + 2)[0], off + 4
    elif linktype == LINKTYPE_LINUX_SLL:
        alen = struct.unpack_from("!H", frame, 4)[0]
        src_mac = _mac(frame[6:6 + min(alen, 6)]) if alen == 6 else ""
        etype, off = struct.unpack_from("!H", frame, 14)[0], 16
    else:
        return Frame(proto="unsupported")

    out = Frame(src_mac=src_mac)
    if etype == ETH_ARP:
        htype, ptype, hlen, plen = struct.unpack_from("!HHBB", frame, off)
        if htype == 1 and ptype == ETH_IPV4 and hlen == 6 and plen == 4:
            sha, spa = frame[off + 8:off + 14], frame[off + 14:off + 18]
            out.proto, out.src_ip = "arp", _ip(spa)
            out.event = ArpClaim(_ip(spa), _mac(sha))
        return out
    if etype != ETH_IPV4:
        return out

    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    frag = struct.unpack_from("!H", frame, off + 6)[0] & 0x1FFF
    src, dst = _ip(frame[off + 12:off + 16]), _ip(frame[off + 16:off + 20])
    out.src_ip, out.proto = src, "ipv4"
    l4 = off + ihl
    if frag:
        return out
    if proto == 6:
        dport = struct.unpack_from("!H", frame, l4 + 2)[0]
        flags = frame[l4 + 13]
        out.proto = "tcp"
        if flags & TCP_SYN and not flags & TCP_ACK:
            out.proto, out.event = "tcp_syn", TcpSyn(src, dst, dport)
    elif proto == 17:
        sport, dport = struct.unpack_from("!HH", frame, l4)
        out.proto = "udp"
        if sport == 67 or dport == 68:
            out.proto = "dhcp"
            out.event = _dhcp(frame[l4 + 8:], src, src_mac)
    return out


def _dhcp(bootp: bytes, ip_src: str, eth_src: str) -> DhcpReply | None:
    if len(bootp) < 240 or bootp[236:240] != DHCP_MAGIC:
        return None
    yiaddr = _ip(bootp[16:20])
    opts: dict[int, bytes] = {}
    off = 240
    while off < len(bootp):
        code = bootp[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        length = bootp[off + 1]
        opts[code] = bootp[off + 2:off + 2 + length]
        off += 2 + length
    msg_type = opts.get(53, b"\x00")[0]
    if msg_type not in (DHCP_OFFER, DHCP_ACK):
        return None
    server = _ip(opts[54][:4]) if len(opts.get(54, b"")) >= 4 else ip_src
    router = _ip(opts[3][:4]) if len(opts.get(3, b"")) >= 4 else ""
    dns = _ip(opts[6][:4]) if len(opts.get(6, b"")) >= 4 else ""
    return DhcpReply(server, eth_src, yiaddr, router, dns)


# --- Analysis ---------------------------------------------------------------
@dataclass
class SeenHost:
    mac: str
    ips: set[str] = field(default_factory=set)
    first_frame: int = 0
    first_ts: float = 0.0
    frames: int = 0


@dataclass
class Analysis:
    source: str = ""
    packets: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    hosts: dict[str, SeenHost] = field(default_factory=dict)
    alerts: list[Alert] = field(default_factory=list)
    gateway_ip: str = ""
    gateway_mac: str = ""
    gateway_source: str = ""
    dhcp_servers: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "packets": self.packets,
            "first_ts": iso(self.first_ts), "last_ts": iso(self.last_ts),
            "duration_s": round(self.last_ts - self.first_ts, 3),
            "protocols": dict(self.protocols.most_common()),
            "gateway": {"ip": self.gateway_ip, "mac": self.gateway_mac,
                        "learned_from": self.gateway_source},
            "dhcp_servers": self.dhcp_servers,
            "hosts": [{"mac": h.mac, "ips": sorted(h.ips), "first_frame": h.first_frame,
                       "first_ts": iso(h.first_ts), "frames": h.frames}
                      for h in sorted(self.hosts.values(), key=lambda h: h.first_frame)],
            "ip_conflicts": ip_conflicts(self.hosts),
            "alerts": [a.to_dict() for a in self.alerts],
        }


def _is_local(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_link_local) and not addr.is_unspecified


def ip_conflicts(hosts: dict[str, SeenHost]) -> dict[str, list[str]]:
    """{ip: [macs]} for every IP claimed by more than one MAC: in a capture,
    the clearest single sign of ARP spoofing."""
    owners: dict[str, list[str]] = {}
    for h in hosts.values():
        for ip in h.ips:
            owners.setdefault(ip, []).append(h.mac)
    return {ip: sorted(macs) for ip, macs in owners.items() if len(macs) > 1}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else ""


def analyze_frames(frames: Iterable[tuple[float, int, bytes]], source: str = "",
                   gateway_ip: str = "", gateway_mac: str = "",
                   known: dict[str, str] | None = None, dhcp_servers: Iterable[str] = (),
                   scan_threshold: int = 15, scan_window: float = 10.0) -> Analysis:
    """Replay frames through the detectors.

    With no gateway given, the gateway is learned from the first DHCP server's
    router option, and its MAC from the first ARP claim for that IP (trust on
    first use, same as live monitoring).
    """
    result = Analysis(source=source, gateway_ip=gateway_ip, gateway_mac=gateway_mac,
                      gateway_source="argument" if gateway_ip else "")
    arp = ArpWatcher(known or {}, gateway_ip or None, gateway_mac or None)
    w = Watchers(port_scan=PortScanDetector(scan_threshold, scan_window), arp=arp,
                 dhcp=DhcpWatcher(set(dhcp_servers)))
    servers: dict[str, dict] = {}

    for n, (ts, linktype, raw) in enumerate(frames, start=1):
        result.packets = n
        result.first_ts = result.first_ts or ts
        result.last_ts = ts
        f = decode(linktype, raw)
        result.protocols[f.proto] += 1
        if f.src_mac and f.src_mac != "ff:ff:ff:ff:ff:ff":
            h = result.hosts.get(f.src_mac)
            if h is None:
                h = result.hosts[f.src_mac] = SeenHost(f.src_mac, first_frame=n, first_ts=ts)
            h.frames += 1
            # A router forwards traffic from the whole internet under its own
            # MAC, so only local (private) source addresses describe the host.
            if f.src_ip and f.proto != "malformed" and _is_local(f.src_ip):
                h.ips.add(f.src_ip)

        ev = f.event
        if isinstance(ev, DhcpReply):
            servers.setdefault(ev.server_ip, {"server_ip": ev.server_ip, "server_mac": ev.server_mac,
                                              "router": ev.router, "dns": ev.dns, "first_frame": n})
            # Learn the gateway from the first (trusted) DHCP server.
            if not arp.gateway_ip and ev.router and len(servers) == 1:
                arp.gateway_ip = result.gateway_ip = ev.router
                result.gateway_source = "DHCP router option"
                if ev.router == ev.server_ip and ev.server_mac:
                    arp.gateway_mac = result.gateway_mac = ev.server_mac
        elif isinstance(ev, ArpClaim) and arp.gateway_ip and not arp.gateway_mac \
                and ev.ip == arp.gateway_ip:
            arp.gateway_mac = result.gateway_mac = ev.mac  # trust on first use
            result.gateway_source = result.gateway_source or "first ARP claim"

        if ev is None:
            continue
        alert = dispatch(ev, ts, w)
        if alert:
            alert.ts = iso(ts)
            alert.details.update({"frame": n, "evidence": source or "capture"})
            result.alerts.append(alert)

    result.dhcp_servers = list(servers.values())
    return result


def analyze(path: Path | str, **kw) -> Analysis:
    return analyze_frames(read_capture(path), source=Path(path).name, **kw)
