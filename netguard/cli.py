"""
Command-line interface.

    netguard baseline              learn what "normal" looks like
    netguard scan                  one check against the baseline
    netguard watch                 keep checking (Ctrl+C to stop)
    netguard serve --open          web dashboard + background monitoring
    netguard hosts | alerts        inspect the database
    netguard trust/untrust/forget  manage devices
    netguard report -o r.html      HTML security report
    netguard update-oui            download the full MAC vendor list
    netguard dhcp-check            look for rogue DHCP servers (scapy + admin)
    netguard test-notify           send a test alert to every configured sink
    netguard demo                  dashboard with a fictional network

Settings come from netguard.toml (see netguard.example.toml); flags win.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__, discovery, oui
from .config import Config
from .engine import Monitor
from .fingerprint import TYPE_LABELS
from .models import Alert, Severity
from .notify import Notifier, build_sinks, format_alert, is_tty
from .store import Store

logger = logging.getLogger("netguard")


# --- Argument parsing -------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguard", description="Lightweight LAN intrusion detection.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", type=Path, default=Path("netguard.db"),
                        help="SQLite database path (default: netguard.db)")
    parser.add_argument("-c", "--config", type=Path,
                        help="TOML config file (default: ./netguard.toml if present)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    def scan_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("-s", "--subnet", help="CIDR to watch (default: /24 around your gateway)")
        p.add_argument("--no-ports", action="store_true", help="Skip the per-host port check")
        p.add_argument("-w", "--workers", type=int, help="Concurrent ARP lookups (threads)")

    def monitor_opts(p: argparse.ArgumentParser) -> None:
        scan_opts(p)
        p.add_argument("-i", "--interval", type=float, help="Seconds between scans")
        p.add_argument("--sniff", action="store_true",
                       help="Live ARP-spoof, rogue-DHCP and port-scan detection (scapy + admin)")
        p.add_argument("--iface", help="Capture interface for --sniff")
        p.add_argument("--log", help="Append alerts to this JSON-lines file")

    scan_opts(sub.add_parser("baseline", help="Record current devices/ports as trusted"))

    p = sub.add_parser("scan", help="Run one check against the baseline")
    scan_opts(p)
    p.add_argument("--log", help="Append alerts to this JSON-lines file")

    monitor_opts(sub.add_parser("watch", help="Check repeatedly until Ctrl+C"))

    p = sub.add_parser("serve", help="Web dashboard with background monitoring")
    monitor_opts(p)
    p.add_argument("--host", help="Listen address (default 127.0.0.1)")
    p.add_argument("--port", type=int, help="Listen port (default 8000)")
    p.add_argument("--token", help="Require this token (needed for non-localhost)")
    p.add_argument("--no-monitor", action="store_true", help="View-only: don't scan")
    p.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    p.add_argument("--reload", action="store_true",
                   help="Restart automatically when NetGuard's files change (for background use)")

    sub.add_parser("hosts", help="List known devices")

    p = sub.add_parser("alerts", help="Show alert history")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.add_argument("--min", dest="min_severity", default="INFO",
                   choices=[s.name for s in Severity], help="Minimum severity")
    p.add_argument("--open", dest="unacked", action="store_true",
                   help="Open alerts only (new or investigating)")

    for name, text in (("trust", "Mark a device as trusted"),
                       ("untrust", "Mark a device as untrusted"),
                       ("forget", "Remove a device from the baseline")):
        sub.add_parser(name, help=text).add_argument("mac", help="MAC address, any format")

    p = sub.add_parser("report", help="Write an HTML security report")
    p.add_argument("-d", "--days", type=int, default=7)
    p.add_argument("-o", "--output", type=Path, default=Path("netguard-report.html"))

    p = sub.add_parser("update-oui", help="Download the IEEE MAC vendor registry")
    p.add_argument("--file", type=Path, help="Import a manually downloaded oui.txt instead")

    p = sub.add_parser("dhcp-check", help="Actively probe for rogue DHCP servers")
    p.add_argument("--iface", help="Interface to probe on")
    p.add_argument("-t", "--timeout", type=float, default=5.0)

    sub.add_parser("test-notify", help="Send a test alert to every configured sink")

    p = sub.add_parser("demo", help="Dashboard with a fictional network (no scanning)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-open", action="store_true", help="Don't open a browser")
    return parser


def load_config(args: argparse.Namespace) -> Config:
    """Config file, then command-line overrides."""
    try:
        cfg = Config.load(args.config)
    except (OSError, ValueError) as exc:
        sys.exit(f"Config error: {exc}")
    for flag, section, key in (
        ("subnet", cfg.scan, "subnet"), ("workers", cfg.scan, "workers"),
        ("interval", cfg.scan, "interval"), ("iface", cfg.sniff, "iface"),
        ("log", cfg.alerts, "log"), ("host", cfg.web, "host"),
        ("port", cfg.web, "port"), ("token", cfg.web, "token"),
    ):
        value = getattr(args, flag, None)
        if value is not None:
            setattr(section, key, value)
    if getattr(args, "no_ports", False):
        cfg.scan.ports = False
    if getattr(args, "sniff", False):
        cfg.sniff.enabled = True
    return cfg


# --- Commands ---------------------------------------------------------------
def cmd_baseline(store: Store, args, cfg: Config) -> None:
    try:
        Monitor(args.db, cfg).scan_once(store, learn=True)
    except RuntimeError as exc:
        sys.exit(str(exc))
    print(f"Baseline saved: {len(store.all_hosts())} devices trusted in {args.db}")
    cmd_hosts(store, args, cfg)


def cmd_scan(store: Store, args, cfg: Config) -> None:
    notifier = Notifier(store, build_sinks(cfg.notify, cfg.alerts.log),
                        cfg.alerts.suppress_minutes)
    try:
        alerts = Monitor(args.db, cfg).scan_once(store)
    except RuntimeError as exc:
        sys.exit(str(exc))
    for a in sorted(alerts, key=lambda a: a.severity, reverse=True):
        notifier.emit(a)
    if not alerts:
        print("No changes from baseline.")
    Notifier._pool.shutdown(wait=True)  # let webhooks/email finish before exiting


def cmd_watch(store: Store, args, cfg: Config) -> None:
    print(f"Watching every {cfg.scan.interval:.0f}s. Ctrl+C to stop.")
    monitor = Monitor(args.db, cfg)
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
        print("\nStopped.")


def cmd_serve(store: Store, args, cfg: Config) -> None:
    from .web import serve
    monitor = None if args.no_monitor else Monitor(args.db, cfg, quiet=False)
    serve(args.db, cfg.web.host, cfg.web.port, monitor, cfg.web.token, args.open,
          reload=args.reload)


def cmd_hosts(store: Store, args, cfg: Config) -> None:
    hosts = store.all_hosts()
    if not hosts:
        print("No devices recorded yet. Run `netguard baseline` first.")
        return
    ports = store.all_ports()
    print(f"{'IP':<16} {'MAC':<18} {'TRUST':<6} {'TYPE':<15} {'PORTS':<18} NAME / VENDOR")
    for h in hosts:
        plist = ",".join(str(p.port) for p in ports.get(h.mac, []))
        name = " ".join(x for x in (h.hostname, f"({h.vendor})" if h.vendor else "") if x)
        dtype = TYPE_LABELS.get(h.device_type, h.device_type)
        print(f"{h.ip:<16} {h.mac:<18} {'yes' if h.trusted else 'NO':<6} "
              f"{dtype[:15]:<15} {plist[:18]:<18} {name}")


def cmd_alerts(store: Store, args, cfg: Config) -> None:
    alerts = store.recent_alerts(args.limit, Severity[args.min_severity],
                                 unacked_only=args.unacked)
    if not alerts:
        print("No alerts.")
    color = is_tty()
    for a in reversed(alerts):  # oldest first, like a log
        print(format_alert(a, color))


def _mac_command(store: Store, mac: str, action, verb: str) -> None:
    mac = discovery.normalize_mac(mac)
    if action(mac):
        print(f"{verb} {mac}")
    else:
        sys.exit(f"Unknown MAC {mac}; see `netguard hosts`")


def cmd_trust(store: Store, args, cfg: Config) -> None:
    _mac_command(store, args.mac, lambda m: store.set_trusted(m, True), "Trusted")


def cmd_untrust(store: Store, args, cfg: Config) -> None:
    _mac_command(store, args.mac, lambda m: store.set_trusted(m, False), "Untrusted")


def cmd_forget(store: Store, args, cfg: Config) -> None:
    _mac_command(store, args.mac, store.forget_host, "Forgot")


def cmd_report(store: Store, args, cfg: Config) -> None:
    from .report import build_report
    args.output.write_text(build_report(store, args.days), encoding="utf-8")
    print(f"Report written to {args.output.resolve()}")


def cmd_update_oui(store: Store, args, cfg: Config) -> None:
    try:
        n = oui.update(args.file)
    except Exception as exc:
        sys.exit(f"Update failed: {exc}\n"
                 f"Tip: download {oui.IEEE_URL} in a browser and run "
                 "`netguard update-oui --file oui.txt`")
    print(f"Installed {n:,} vendors to {oui.OUI_FILE}")
    # Re-label known hosts with the richer table.
    for h in store.all_hosts():
        vendor = discovery.lookup_vendor(h.mac)
        if vendor and vendor != h.vendor:
            h.vendor = vendor
            store.upsert_host(h)


def cmd_dhcp_check(store: Store, args, cfg: Config) -> None:
    from . import sniffer
    from .engine import DHCP_SERVERS_KEY
    if not sniffer.scapy_available():
        sys.exit("dhcp-check needs scapy: pip install scapy (and Npcap on Windows), run as admin")
    try:
        servers = sniffer.probe_dhcp_servers(args.timeout, args.iface)
    except (PermissionError, OSError) as exc:
        sys.exit(f"Probe failed: {exc} (run as administrator/root)")

    allowed = set(cfg.sniff.dhcp_servers) or set(filter(None, (
        store.get_meta(DHCP_SERVERS_KEY) or "").split(",")))
    if not servers:
        print("No DHCP server answered.")
        return
    for s in servers:
        flag = "" if not allowed or s["server_ip"] in allowed else "   <-- NOT ALLOWED"
        print(f"{s['server_ip']:<16} {s['server_mac']}  offered {s['offered_ip']:<15} "
              f"router {s['router'] or '?':<15} dns {s['dns'] or '?'}{flag}")
    if len(servers) > 1:
        print(f"\nWARNING: {len(servers)} DHCP servers answered. Normally there is one.")


def cmd_test_notify(store: Store, args, cfg: Config) -> None:
    sinks = build_sinks(cfg.notify, cfg.alerts.log)
    if not sinks:
        sys.exit("No [[notify]] sinks configured in netguard.toml")
    notifier = Notifier(store, sinks, suppress_minutes=0)
    notifier.emit(Alert(Severity.CRITICAL, "test",
                        "Test alert from NetGuard. If you can read this, notifications work."))
    Notifier._pool.shutdown(wait=True)
    print(f"Sent to {len(sinks)} sink(s): {', '.join(type(s).__name__ for s in sinks)}")


def cmd_demo(store: Store, args, cfg: Config) -> None:
    from .demo import build_demo_db
    from .web import serve
    db = build_demo_db(Path("netguard-demo.db"))
    print("Demo network loaded (fictional data, view-only).")
    serve(db, "127.0.0.1", args.port, monitor=None, open_browser=not args.no_open)


COMMANDS = {
    "baseline": cmd_baseline, "scan": cmd_scan, "watch": cmd_watch, "serve": cmd_serve,
    "hosts": cmd_hosts, "alerts": cmd_alerts, "trust": cmd_trust, "untrust": cmd_untrust,
    "forget": cmd_forget, "report": cmd_report, "update-oui": cmd_update_oui,
    "dhcp-check": cmd_dhcp_check, "test-notify": cmd_test_notify, "demo": cmd_demo,
}


# --- Entry point ------------------------------------------------------------
def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO
    if sys.stderr is None:
        # Running windowless (pythonw / scheduled task): log to a file instead.
        logging.basicConfig(filename="netguard.log", level=level,
                            format="%(asctime)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    cfg = load_config(args)
    with Store(args.db) as store:
        COMMANDS[args.command](store, args, cfg)
