"""
The monitoring engine shared by the CLI (`scan`, `watch`) and the dashboard.

A Monitor owns one scan cycle — discover hosts, check ports, fingerprint,
diff against the baseline, notify — plus the optional sniffer, and a loop
that repeats the cycle on an interval or on demand ("Scan now" in the UI).
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, fingerprint, portscan
from .config import Config
from .detect import (GATEWAY_IP_KEY, GATEWAY_MAC_KEY, ArpWatcher, DhcpWatcher,
                     PortScanDetector, check_hosts, check_ports)
from .models import Alert, Event, Host
from .notify import Notifier, build_sinks
from .store import Store, now_iso

logger = logging.getLogger(__name__)

DHCP_SERVERS_KEY = "dhcp_servers"
BASELINE_AT_KEY = "baseline_at"
SCAN_STARTED_KEY = "scan_started"


@dataclass
class Status:
    """What the dashboard shows in its header. Read from other threads."""

    scanning: bool = False
    last_scan: str = ""
    last_duration: float = 0.0
    last_error: str = ""
    next_scan: float = 0.0          # time.time() of the next scheduled scan
    subnet: str = ""
    gateway: str = ""
    local_ip: str = ""
    sniffer: list[str] = field(default_factory=list)
    interval: float = 0.0


class Monitor:
    def __init__(self, db_path: Path | str, config: Config, quiet: bool = False) -> None:
        self.db_path = db_path
        self.config = config
        self.quiet = quiet
        self.status = Status(interval=config.scan.interval)
        self._sniffed: queue.Queue[Alert] = queue.Queue()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._scan_lock = threading.Lock()
        self._arp: ArpWatcher | None = None
        self._dhcp: DhcpWatcher | None = None
        self._stop_sniffer: threading.Event | None = None

    # -- single cycle --------------------------------------------------------
    def resolve_target(self, store: Store) -> tuple[str, str | None]:
        gateway = discovery.default_gateway() or store.get_meta(GATEWAY_IP_KEY)
        subnet = self.config.scan.subnet or discovery.guess_subnet(gateway)
        if not subnet:
            raise RuntimeError("Could not detect your gateway; set a subnet, "
                               "e.g. --subnet 192.168.1.0/24")
        self.status.subnet, self.status.gateway = subnet, gateway or ""
        self.status.local_ip = discovery.local_ip(gateway) or ""
        return subnet, gateway

    def scan_once(self, store: Store, learn: bool = False) -> list[Alert]:
        """Run one full cycle and return the alerts (not yet emitted)."""
        with self._scan_lock:
            self.status.scanning = True
            started = time.monotonic()
            try:
                alerts = self._scan(store, learn)
                if learn:
                    store.set_meta(BASELINE_AT_KEY, now_iso())
                return alerts
            finally:
                self.status.scanning = False
                self.status.last_scan = now_iso()
                self.status.last_duration = round(time.monotonic() - started, 1)

    def _scan(self, store: Store, learn: bool) -> list[Alert]:
        cfg = self.config.scan
        subnet, gateway = self.resolve_target(store)
        logger.info("Subnet %s, gateway %s", subnet, gateway or "unknown")

        before = {h.mac: h for h in store.all_hosts()}
        ports_before = {mac: {p.port for p in ps} for mac, ps in store.open_ports().items()}
        prev_scan = store.get_meta(SCAN_STARTED_KEY)
        store.set_meta(SCAN_STARTED_KEY, now_iso())

        hosts = discovery.discover(subnet, workers=cfg.workers)
        alerts = check_hosts(store, hosts, gateway, learn=learn)
        self._record_presence(store, before, hosts, prev_scan)

        for h in hosts:
            open_ports: list = []
            if cfg.ports:
                had_baseline = store.has_port_baseline(h.mac)
                open_ports = portscan.scan_host(h.mac, h.ip)
                alerts += check_ports(store, h, open_ports, learn=learn)
                if had_baseline:
                    # Debounced view (see Store.open_ports): a port that
                    # misses one probe is still "open", so no flapping events.
                    after = {p.port for p in store.open_ports().get(h.mac, [])}
                    self._record_port_changes(store, h, ports_before.get(h.mac, set()), after)
            port_numbers = {p.port for p in store.get_ports(h.mac)} or \
                           {p.port for p in open_ports}
            store.set_device_type(h.mac, fingerprint.classify(h, port_numbers, gateway))

        self._refresh_watchers(store)
        return alerts

    # -- activity log --------------------------------------------------------
    @staticmethod
    def _record_presence(store: Store, before: dict[str, Host], seen: list[Host],
                         prev_scan: str | None = None) -> None:
        """Log arrivals, departures and IP changes: the timeline an analyst
        reconstructs during an investigation.

        A device only goes "offline" after missing two scans in a row (it
        wasn't seen since before the previous scan started). Phones and IoT
        in power-save regularly miss a single ARP probe.
        """
        seen_macs = {h.mac for h in seen}
        for h in seen:
            old = before.get(h.mac)
            if old is None:
                store.add_event(Event("first_seen", f"First seen: {h.label()}", h.mac, h.ip,
                                      details={"vendor": h.vendor, "hostname": h.hostname}))
                continue
            name = old.alias or h.hostname or old.hostname or h.mac
            if old.ip and old.ip != h.ip:
                store.add_event(Event("ip_change", f"{name} moved {old.ip} → {h.ip}",
                                      h.mac, h.ip, details={"old_ip": old.ip, "new_ip": h.ip}))
            if not old.online:
                store.add_event(Event("online", f"{name} came online at {h.ip}", h.mac, h.ip))
        for mac, old in before.items():
            missed_twice = not prev_scan or old.last_seen < prev_scan
            if mac not in seen_macs and old.online and missed_twice:
                store.set_online(mac, False)
                name = old.alias or old.hostname or mac
                store.add_event(Event("offline", f"{name} went offline (last at {old.ip})",
                                      mac, old.ip))

    @staticmethod
    def _record_port_changes(store: Store, h: Host, old: set[int], new: set[int]) -> None:
        name = h.alias or h.hostname or h.ip
        for port in sorted(new - old):
            store.add_event(Event("port_open", f"{name}: port {port} opened", h.mac, h.ip,
                                  details={"port": port}))
        for port in sorted(old - new):
            store.add_event(Event("port_closed", f"{name}: port {port} closed", h.mac, h.ip,
                                  details={"port": port}))

    # -- sniffer -------------------------------------------------------------
    def start_sniffer(self, store: Store) -> None:
        from . import sniffer

        sc = self.config.sniff
        if not sniffer.scapy_available():
            raise RuntimeError("Sniffing needs scapy: pip install scapy "
                               "(and Npcap on Windows), then run as admin")
        _, gateway = self.resolve_target(store)

        watchers = sniffer.Watchers()
        if sc.port_scan:
            watchers.port_scan = PortScanDetector(sc.port_scan_threshold, sc.port_scan_window)
        if sc.arp:
            watchers.arp = self._arp = ArpWatcher()
        if sc.dhcp:
            allowed = set(sc.dhcp_servers) or set(filter(None, (
                store.get_meta(DHCP_SERVERS_KEY) or "").split(",")))
            watchers.dhcp = self._dhcp = DhcpWatcher(allowed)
        self._refresh_watchers(store)

        me = self.status.local_ip
        self._stop_sniffer = sniffer.start_sniffer(
            self._sniffed.put, {me} if me else set(), watchers, iface=sc.iface or None)
        self.status.sniffer = [n for n in ("port_scan", "arp", "dhcp")
                               if getattr(watchers, n)]

    def _refresh_watchers(self, store: Store) -> None:
        """Give the ARP watcher the latest IP->MAC bindings after each scan."""
        if self._arp:
            known = {h.ip: h.mac for h in store.all_hosts() if h.ip}
            self._arp.update(known, store.get_meta(GATEWAY_IP_KEY),
                             store.get_meta(GATEWAY_MAC_KEY))

    # -- loop ----------------------------------------------------------------
    def trigger_scan(self) -> bool:
        """Ask the loop to scan now. False if a scan is already running."""
        if self.status.scanning:
            return False
        self._wake.set()
        return True

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def run(self, interval: float | None = None) -> None:
        """Scan, wait, repeat until stop(). Owns its own Store (thread-safe)."""
        interval = interval or self.config.scan.interval
        self.status.interval = interval
        with Store(self.db_path) as store:
            notifier = Notifier(store, build_sinks(self.config.notify, self.config.alerts.log,
                                                self.config.alerts.log_format),
                                self.config.alerts.suppress_minutes, quiet=self.quiet)
            if self.config.sniff.enabled:
                try:
                    self.start_sniffer(store)
                except RuntimeError as exc:
                    logger.error("%s", exc)
                    self.status.last_error = str(exc)

            store.prune(keep_days=90)
            # With an empty database every device would be "new"; treat the
            # first scan as the baseline instead (same as `netguard baseline`).
            learn = not store.all_hosts()
            if learn:
                logger.warning("No baseline yet: trusting the devices found by the first scan")
            try:
                while not self._stop.is_set():
                    try:
                        for a in sorted(self.scan_once(store, learn=learn),
                                        key=lambda a: a.severity, reverse=True):
                            notifier.emit(a)
                        self.status.last_error = ""
                        learn = False
                    except Exception as exc:  # keep monitoring through a bad cycle
                        logger.exception("Scan failed")
                        self.status.last_error = str(exc)
                    self._wait(interval, store, notifier)
            finally:
                if self._stop_sniffer:
                    self._stop_sniffer.set()

    def _wait(self, interval: float, store: Store, notifier: Notifier) -> None:
        """Sleep until the next scan, emitting sniffer alerts as they arrive."""
        self._wake.clear()
        self.status.next_scan = time.time() + interval
        deadline = time.monotonic() + interval
        while not self._wake.is_set() and (remaining := deadline - time.monotonic()) > 0:
            try:
                alert = self._sniffed.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if alert.kind == "dhcp_server_learned" and self._dhcp:
                store.set_meta(DHCP_SERVERS_KEY, ",".join(sorted(self._dhcp.allowed)))
            notifier.emit(alert)
        self.status.next_scan = 0.0
