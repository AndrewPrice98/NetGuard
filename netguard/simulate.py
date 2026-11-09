"""
Attack simulation and detection validation.

A detection you have never seen fire is a detection you don't know works.
This module builds byte-accurate packet captures of attacks (and of normal
traffic) and replays them through the real detectors, the same way
Atomic Red Team or a purple-team exercise proves coverage:

    netguard simulate -o samples/     write every scenario as a .pcap
    netguard validate                 replay all scenarios, print a pass/fail matrix

Each scenario states what it *expects*: detections that must fire, and
detections that must not (false-positive checks). Two scenarios are
deliberately benign, and one documents a known blind spot (a low-and-slow
scan below the threshold) so the gap is explicit rather than hidden.

Nothing here touches a network: frames are built in memory with `struct`
and written to files you can open in Wireshark. The addresses are the same
fictional 192.168.1.0/24 home network used by `netguard demo`.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import Severity
from .pcap import LINKTYPE_ETHERNET, Analysis, analyze_frames

# --- The fictional network --------------------------------------------------
GW = ("192.168.1.1", "f0:9f:c2:10:20:01")         # router, DHCP server
LAPTOP = ("192.168.1.20", "a4:83:e7:2b:11:5c")    # victim
NAS = ("192.168.1.10", "00:11:32:aa:01:02")
PRINTER = ("192.168.1.12", "3c:2a:f4:51:7e:90")
ATTACKER = ("192.168.1.87", "de:ad:be:ef:13:37")
ROGUE = ("192.168.1.92", "b8:27:eb:66:66:66")      # Raspberry Pi running dnsmasq
BROADCAST = "ff:ff:ff:ff:ff:ff"
INTERNET = "93.184.216.34"
T0 = datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc).timestamp()

Frames = list[tuple[float, bytes]]


# --- Packet builders --------------------------------------------------------
def _mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ether(dst: str, src: str, etype: int, payload: bytes) -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", etype) + payload


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    """op 1 = who-has (request), 2 = is-at (reply)."""
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + \
        _mac(sha) + _ip(spa) + _mac(tha) + _ip(tpa)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF,
                      0x4000, 64, proto, 0, _ip(src), _ip(dst))
    hdr = hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src: str, dst: str, sport: int, dport: int, flags: int, seq: int = 0, ack: int = 0) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(seg))
    return seg[:16] + struct.pack("!H", _checksum(pseudo + seg)) + seg[18:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 17, length)
    csum = _checksum(pseudo + seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def dhcp(op: int, xid: int, client_mac: str, yiaddr: str = "0.0.0.0",
         siaddr: str = "0.0.0.0", options: list[tuple[int, bytes]] = ()) -> bytes:
    body = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000,
                       _ip("0.0.0.0"), _ip(yiaddr), _ip(siaddr), _ip("0.0.0.0"))
    body += _mac(client_mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    for code, value in options:
        body += bytes([code, len(value)]) + value
    return body + b"\xff"


SYN, ACK, RST = 0x02, 0x10, 0x04


# --- Traffic snippets -------------------------------------------------------
def arp_exchange(t: float, asker: tuple, target: tuple) -> Frames:
    """`asker` asks who has target's IP; target answers."""
    return [
        (t, ether(BROADCAST, asker[1], 0x0806, arp(1, asker[1], asker[0], "00:00:00:00:00:00", target[0]))),
        (t + 0.002, ether(asker[1], target[1], 0x0806, arp(2, target[1], target[0], asker[1], asker[0]))),
    ]


def dhcp_lease(t: float, client_mac: str, offered: str, server: tuple = GW,
               router: str = GW[0], dns: str = GW[0], xid: int = 0x1A2B3C4D) -> Frames:
    """DISCOVER from the client, OFFER from `server`."""
    discover = dhcp(1, xid, client_mac, options=[(53, b"\x01"), (55, b"\x01\x03\x06")])
    offer = dhcp(2, xid, client_mac, yiaddr=offered, siaddr=server[0], options=[
        (53, b"\x02"), (54, _ip(server[0])), (51, struct.pack("!I", 86400)),
        (1, _ip("255.255.255.0")), (3, _ip(router)), (6, _ip(dns))])
    return [
        (t, ether(BROADCAST, client_mac, 0x0800,
                  ipv4("0.0.0.0", "255.255.255.255", 17, udp("0.0.0.0", "255.255.255.255", 68, 67, discover)))),
        (t + 0.004, ether(BROADCAST, server[1], 0x0800,
                          ipv4(server[0], "255.255.255.255", 17, udp(server[0], "255.255.255.255", 67, 68, offer)))),
    ]


def tcp_handshake(t: float, client: tuple, server_ip: str, server_mac: str, dport: int,
                  sport: int = 50000) -> Frames:
    return [
        (t, ether(server_mac, client[1], 0x0800, ipv4(client[0], server_ip, 6,
                                                       tcp(client[0], server_ip, sport, dport, SYN, 1000)))),
        (t + 0.01, ether(client[1], server_mac, 0x0800, ipv4(server_ip, client[0], 6,
                                                              tcp(server_ip, client[0], dport, sport, SYN | ACK, 5000, 1001)))),
        (t + 0.011, ether(server_mac, client[1], 0x0800, ipv4(client[0], server_ip, 6,
                                                               tcp(client[0], server_ip, sport, dport, ACK, 1001, 5001)))),
    ]


def normal_network(t: float) -> Frames:
    """A quiet minute on a home network: a laptop gets a lease, finds the
    router, browses, and reaches the NAS."""
    frames = dhcp_lease(t, LAPTOP[1], LAPTOP[0])
    frames += arp_exchange(t + 1, LAPTOP, GW)
    frames += arp_exchange(t + 2, LAPTOP, NAS)
    frames += arp_exchange(t + 3, GW, PRINTER)
    for i, port in enumerate((443, 443, 80, 443)):
        frames += tcp_handshake(t + 4 + i, LAPTOP, INTERNET, GW[1], port, 50100 + i)
    frames += tcp_handshake(t + 9, LAPTOP, NAS[0], NAS[1], 445, 50200)
    return frames


def port_scan(t: float, src: tuple, target: tuple, ports: list[int], spacing: float) -> Frames:
    frames: Frames = []
    open_ports = {22, 80, 443, 445, 5000}
    for i, port in enumerate(ports):
        ts = t + i * spacing
        frames.append((ts, ether(target[1], src[1], 0x0800,
                                 ipv4(src[0], target[0], 6, tcp(src[0], target[0], 61000, port, SYN, 7000 + i), i))))
        reply = SYN | ACK if port in open_ports else RST | ACK
        frames.append((ts + 0.0005, ether(src[1], target[1], 0x0800,
                                          ipv4(target[0], src[0], 6, tcp(target[0], src[0], port, 61000, reply, 0, 7001 + i)))))
    return frames


def gateway_poisoning(t: float, victim: tuple, count: int = 10, interval: float = 2.0) -> Frames:
    """arpspoof-style: unsolicited replies telling the victim the gateway is
    at the attacker's MAC, repeated to keep the victim's cache poisoned."""
    return [(t + k * interval, ether(victim[1], ATTACKER[1], 0x0806,
                                     arp(2, ATTACKER[1], GW[0], victim[1], victim[0])))
            for k in range(count)]


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
             3306, 3389, 5900, 8080, 8443, 5000, 9100, 139, 554, 1433, 1521, 2049, 6379, 27017]


# --- Scenarios --------------------------------------------------------------
@dataclass
class Scenario:
    name: str
    title: str
    technique: str           # ATT&CK ID, or "" for benign traffic
    description: str
    build: Callable[[], Frames]
    expect: set[str] = field(default_factory=set)   # must fire
    forbid: set[str] = field(default_factory=set)   # must not fire ("*" = nothing above INFO)
    gap: bool = False        # documents a known blind spot


def _benign() -> Frames:
    return normal_network(T0)


def _arp_spoof_gateway() -> Frames:
    return normal_network(T0) + arp_exchange(T0 + 20, ATTACKER, GW) + gateway_poisoning(T0 + 30, LAPTOP)


def _arp_poison_host() -> Frames:
    # Attacker tells the router that the laptop's IP is at the attacker's MAC
    # (the other half of a two-way MITM, aimed at one host).
    frames = normal_network(T0)
    frames += [(T0 + 30 + k * 2, ether(GW[1], ATTACKER[1], 0x0806,
                                       arp(2, ATTACKER[1], LAPTOP[0], GW[1], GW[0]))) for k in range(5)]
    return frames


def _rogue_dhcp() -> Frames:
    frames = normal_network(T0)
    # A phone joins; the real router AND a rogue server both answer. The rogue
    # offer names itself as gateway and DNS: interception without ARP tricks.
    phone = "8c:85:90:6a:c3:01"
    frames += dhcp_lease(T0 + 40, phone, "192.168.1.30", xid=0x55AA0001)
    frames += dhcp_lease(T0 + 40.003, phone, "192.168.1.200", server=ROGUE,
                         router=ROGUE[0], dns=ROGUE[0], xid=0x55AA0001)[1:]
    return frames


def _port_scan() -> Frames:
    return normal_network(T0) + port_scan(T0 + 30, ATTACKER, NAS, TOP_PORTS, 0.05)


def _slow_scan() -> Frames:
    # 20 ports, one every 15 s: never 15 distinct ports inside the 10 s window.
    return normal_network(T0) + port_scan(T0 + 30, ATTACKER, NAS, TOP_PORTS[:20], 15.0)


def _kill_chain() -> Frames:
    """The demo incident, end to end: join, scan, poison the gateway."""
    frames = normal_network(T0)
    frames += dhcp_lease(T0 + 60, ATTACKER[1], ATTACKER[0], xid=0x0BADC0DE)
    frames += arp_exchange(T0 + 61, ATTACKER, GW)
    frames += port_scan(T0 + 90, ATTACKER, NAS, TOP_PORTS, 0.02)
    frames += port_scan(T0 + 95, ATTACKER, LAPTOP, TOP_PORTS, 0.02)
    frames += gateway_poisoning(T0 + 180, LAPTOP, count=15)
    return sorted(frames, key=lambda f: f[0])


SCENARIOS: list[Scenario] = [
    Scenario("benign_baseline", "Normal home-network traffic", "",
             "DHCP lease, ARP resolution, HTTPS and SMB sessions. Must stay quiet "
             "apart from learning the DHCP server.",
             _benign, expect={"dhcp_server_learned"}, forbid={"*"}),
    Scenario("arp_spoof_gateway", "ARP spoofing of the gateway", "T1557.002",
             "arpspoof/Bettercap-style: repeated unsolicited ARP replies telling the "
             "laptop that the router's IP is at the attacker's MAC.",
             _arp_spoof_gateway, expect={"gateway_arp_spoof"}),
    Scenario("arp_poison_host", "ARP poisoning of a single host", "T1557.002",
             "The attacker tells the router that the laptop's IP is at its MAC.",
             _arp_poison_host, expect={"arp_mismatch"}, forbid={"gateway_arp_spoof"}),
    Scenario("rogue_dhcp", "Rogue DHCP server", "T1557.003",
             "A Raspberry Pi answers DHCP requests, naming itself as gateway and DNS.",
             _rogue_dhcp, expect={"rogue_dhcp"}),
    Scenario("port_scan", "TCP SYN port scan", "T1046",
             "nmap -sS style: 30 well-known ports probed on the NAS in 1.5 s.",
             _port_scan, expect={"port_scan"}),
    Scenario("slow_scan_below_threshold", "Low-and-slow port scan (known gap)", "T1046",
             "20 ports at one probe per 15 s stays under the 15-ports-in-10-s threshold. "
             "Documents a deliberate trade-off: catching this needs a longer window and "
             "more false positives from busy servers.",
             _slow_scan, forbid={"port_scan"}, gap=True),
    Scenario("mitm_kill_chain", "Full adversary-in-the-middle chain", "T1557.002",
             "An attacker joins via DHCP, scans the NAS and the laptop, then poisons the "
             "laptop's ARP cache for the gateway. The capture behind the demo incident.",
             _kill_chain, expect={"port_scan", "gateway_arp_spoof"},
             forbid={"rogue_dhcp"}),
]


def scenario(name: str) -> Scenario:
    for s in SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(f"Unknown scenario {name!r}. Choose from: {', '.join(s.name for s in SCENARIOS)}")


# --- Output -----------------------------------------------------------------
def write_pcap(path: Path, frames: Frames) -> None:
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)]
    for ts, frame in sorted(frames, key=lambda f: f[0]):
        sec = int(ts)
        out.append(struct.pack("<IIII", sec, round((ts - sec) * 1e6), len(frame), len(frame)))
        out.append(frame)
    path.write_bytes(b"".join(out))


def run(s: Scenario) -> Analysis:
    frames = sorted(s.build(), key=lambda f: f[0])
    return analyze_frames(((ts, LINKTYPE_ETHERNET, f) for ts, f in frames), source=f"{s.name}.pcap")


@dataclass
class Result:
    scenario: Scenario
    analysis: Analysis
    fired: set[str]
    missing: set[str]
    unexpected: set[str]

    @property
    def passed(self) -> bool:
        return not self.missing and not self.unexpected


def validate(s: Scenario) -> Result:
    analysis = run(s)
    fired = {a.kind for a in analysis.alerts}
    loud = {a.kind for a in analysis.alerts if a.severity > Severity.INFO}
    unexpected = loud if "*" in s.forbid else fired & s.forbid
    return Result(s, analysis, fired, s.expect - fired, unexpected)


def validate_all() -> list[Result]:
    return [validate(s) for s in SCENARIOS]
