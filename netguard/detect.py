"""
Detection logic: compare what we observe now against the stored baseline.

Every check returns a list of Alerts and updates the store, so repeated
scans don't re-raise the same finding (a rogue host is reported once,
not once per minute).

With `learn=True` the checks record what they see as trusted baseline and
raise nothing — that is how `netguard baseline` works.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

from collections import defaultdict, deque

from .models import Alert, Host, PortState, Severity
from .portscan import RISKY_PORTS
from .store import Store, now_iso

GATEWAY_IP_KEY = "gateway_ip"
GATEWAY_MAC_KEY = "gateway_mac"


# --- Host checks ------------------------------------------------------------
def check_hosts(store: Store, observed: list[Host], gateway_ip: str | None,
                learn: bool = False) -> list[Alert]:
    """Rogue hosts, ARP spoofing, gateway hijacking and IP takeovers."""
    alerts: list[Alert] = []
    ts = now_iso()

    # Snapshot who held each IP *before* this scan, so the order we process
    # hosts in below can't hide an IP changing hands.
    previous_owner: dict[str, Host] = {}
    for h in sorted(store.all_hosts(), key=lambda h: h.last_seen):
        if h.ip:
            previous_owner[h.ip] = h

    ips_by_mac: dict[str, list[str]] = defaultdict(list)
    for h in observed:
        ips_by_mac[h.mac].append(h.ip)

    gateway_mac = next((h.mac for h in observed if h.ip == gateway_ip), None)
    baseline_gw_mac = store.get_meta(GATEWAY_MAC_KEY)

    if not learn:
        # 1. Gateway hijack: the router's MAC is different from the baseline.
        if gateway_mac and baseline_gw_mac and gateway_mac != baseline_gw_mac:
            alerts.append(Alert(
                Severity.CRITICAL, "gateway_mac_changed",
                f"Gateway {gateway_ip} MAC changed {baseline_gw_mac} -> {gateway_mac}. "
                "Possible ARP-spoofing man-in-the-middle.",
                ts, {"ip": gateway_ip, "old_mac": baseline_gw_mac, "new_mac": gateway_mac},
            ))

        # 2. One MAC answering for several IPs. If one of those IPs is the
        #    gateway, someone is impersonating the router.
        for mac, ips in ips_by_mac.items():
            if len(ips) < 2:
                continue
            impersonates_gw = gateway_ip in ips and mac != baseline_gw_mac
            alerts.append(Alert(
                Severity.HIGH if impersonates_gw else Severity.MEDIUM,
                "arp_spoof" if impersonates_gw else "duplicate_mac",
                f"MAC {mac} answers for multiple IPs: {', '.join(sorted(ips))}"
                + (" (including the gateway)" if impersonates_gw else ""),
                ts, {"mac": mac, "ips": sorted(ips)},
            ))

    for h in observed:
        h.last_seen = ts
        known = store.get_host(h.mac)
        prev = previous_owner.get(h.ip)

        if not learn:
            # 3. A trusted device's IP is now held by a different MAC. Normal
            #    DHCP churn does this too, so it's LOW on its own; the
            #    duplicate-MAC / gateway checks above catch the nasty cases.
            if prev and prev.mac != h.mac and prev.trusted and h.ip != gateway_ip:
                alerts.append(Alert(
                    Severity.LOW, "ip_changed_hands",
                    f"{h.ip} moved from {prev.mac} to {h.mac}",
                    ts, {"ip": h.ip, "old_mac": prev.mac, "new_mac": h.mac},
                ))

            # 4. Rogue host: a MAC we've never seen. Reported once; after that
            #    it lives in the DB as untrusted until someone runs `trust`.
            if known is None:
                alerts.append(Alert(
                    Severity.MEDIUM, "new_host",
                    f"New device on the network: {h.label()}",
                    ts, {"mac": h.mac, "ip": h.ip, "hostname": h.hostname,
                         "vendor": h.vendor},
                ))

        h.trusted = learn
        store.upsert_host(h)

    # Trust-on-first-use for the gateway, or re-learn it in baseline mode.
    if gateway_mac and (learn or not baseline_gw_mac):
        store.set_meta(GATEWAY_MAC_KEY, gateway_mac)
        store.set_meta(GATEWAY_IP_KEY, gateway_ip or "")

    return alerts


# --- Port checks ------------------------------------------------------------
def check_ports(store: Store, host: Host, open_ports: list[PortState],
                learn: bool = False) -> list[Alert]:
    """Service drift: a known host has started listening on a new port.

    The first scan of any host is silently recorded as its baseline. Ports
    that close are not alerted on — devices sleep and services restart.
    """
    alerts: list[Alert] = []
    if not learn and store.has_port_baseline(host.mac):
        known = {(p.port, p.proto) for p in store.get_ports(host.mac)}
        for p in open_ports:
            if (p.port, p.proto) in known:
                continue
            risky = p.port in RISKY_PORTS
            alerts.append(Alert(
                Severity.HIGH if risky else Severity.MEDIUM, "new_port",
                f"{host.label()} opened {p.proto}/{p.port}"
                + (f" ({p.service})" if p.service else ""),
                now_iso(), {"mac": host.mac, "ip": host.ip, "port": p.port,
                            "proto": p.proto, "service": p.service},
            ))
    store.record_ports(host.mac, open_ports)
    return alerts


# --- Port-scan detection ----------------------------------------------------
class PortScanDetector:
    """Flag a source that touches many distinct ports in a short window.

    Fed one (source IP, destination port, timestamp) per inbound SYN. Pure
    logic with no I/O, so it's driven by the sniffer in production and by
    plain function calls in the tests.
    """

    def __init__(self, threshold: int = 15, window: float = 10.0,
                 cooldown: float = 60.0) -> None:
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self._hits: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def feed(self, src: str, dst_port: int, ts: float) -> Alert | None:
        hits = self._hits[src]
        hits.append((ts, dst_port))
        while hits and ts - hits[0][0] > self.window:
            hits.popleft()

        ports = {p for _, p in hits}
        if len(ports) < self.threshold:
            return None
        last = self._last_alert.get(src)
        if last is not None and ts - last < self.cooldown:
            return None

        self._last_alert[src] = ts
        return Alert(
            Severity.HIGH, "port_scan",
            f"{src} probed {len(ports)} ports in {self.window:.0f}s",
            now_iso(), {"src": src, "ports": sorted(ports)[:50]},
        )


# --- Passive ARP watching ---------------------------------------------------
class ArpWatcher:
    """Catch ARP spoofing the moment it happens, not at the next scan.

    Every ARP packet carries a claim "IP x is at MAC y". The watcher checks
    each claim against the known bindings. A wrong claim for the gateway is
    the signature of an arpspoof/ettercap-style man-in-the-middle.

    `update()` is called by the monitor after each scan (from another
    thread); it swaps whole dicts, which is atomic in CPython.
    """

    def __init__(self, known: dict[str, str] | None = None,
                 gateway_ip: str | None = None, gateway_mac: str | None = None,
                 cooldown: float = 300.0) -> None:
        self.known: dict[str, str] = dict(known or {})
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.cooldown = cooldown
        self._last_alert: dict[tuple[str, str], float] = {}

    def update(self, known: dict[str, str], gateway_ip: str | None,
               gateway_mac: str | None) -> None:
        self.known = dict(known)
        self.gateway_ip, self.gateway_mac = gateway_ip, gateway_mac

    def _cooled(self, key: tuple[str, str], ts: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and ts - last < self.cooldown:
            return False
        self._last_alert[key] = ts
        return True

    def feed(self, ip: str, mac: str, ts: float) -> Alert | None:
        if not ip or ip == "0.0.0.0":  # ARP probes carry no claim
            return None

        if ip == self.gateway_ip and self.gateway_mac:
            if mac == self.gateway_mac or not self._cooled((ip, mac), ts):
                return None
            return Alert(
                Severity.CRITICAL, "gateway_arp_spoof",
                f"Live ARP traffic claims gateway {ip} is at {mac} "
                f"(expected {self.gateway_mac}). Man-in-the-middle in progress?",
                now_iso(), {"ip": ip, "claimed_mac": mac, "expected_mac": self.gateway_mac},
            )

        expected = self.known.get(ip)
        if expected is None:
            self.known[ip] = mac  # new binding; the scanner reports new hosts
            return None
        if expected == mac:
            return None
        # Accept the new binding after reporting it once: legitimate DHCP
        # reassignment looks the same, and the next scan confirms either way.
        self.known[ip] = mac
        if not self._cooled((ip, mac), ts):
            return None
        return Alert(
            Severity.MEDIUM, "arp_mismatch",
            f"ARP says {ip} is now at {mac} (was {expected})",
            now_iso(), {"ip": ip, "new_mac": mac, "old_mac": expected},
        )


# --- Rogue DHCP detection ---------------------------------------------------
class DhcpWatcher:
    """Flag DHCP offers from any server other than the legitimate one(s).

    A rogue DHCP server can hand out itself as the gateway or DNS server —
    a man-in-the-middle that needs no ARP tricks at all.

    With no servers configured, the first one seen is trusted (and an INFO
    alert says so, so the monitor can persist it).
    """

    def __init__(self, allowed: set[str] | None = None, learn_first: bool = True,
                 cooldown: float = 300.0) -> None:
        self.allowed = set(allowed or ())
        self.learn_first = learn_first
        self.cooldown = cooldown
        self._last_alert: dict[str, float] = {}

    def feed(self, server_ip: str, server_mac: str, offered_ip: str,
             ts: float) -> Alert | None:
        if server_ip in self.allowed:
            return None
        if not self.allowed and self.learn_first:
            self.allowed.add(server_ip)
            return Alert(
                Severity.INFO, "dhcp_server_learned",
                f"Trusting DHCP server {server_ip} ({server_mac})",
                now_iso(), {"server_ip": server_ip, "server_mac": server_mac},
            )
        last = self._last_alert.get(server_ip)
        if last is not None and ts - last < self.cooldown:
            return None
        self._last_alert[server_ip] = ts
        return Alert(
            Severity.CRITICAL, "rogue_dhcp",
            f"Rogue DHCP server {server_ip} ({server_mac}) offered {offered_ip or '?'}; "
            f"expected {', '.join(sorted(self.allowed))}",
            now_iso(), {"server_ip": server_ip, "server_mac": server_mac,
                        "offered_ip": offered_ip, "allowed": sorted(self.allowed)},
        )
