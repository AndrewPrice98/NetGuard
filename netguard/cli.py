"""
Command-line interface.

    netguard baseline              learn what "normal" looks like
    netguard scan                  one check against the baseline
    netguard watch                 keep checking (Ctrl+C to stop)
    netguard serve --open          web dashboard + background monitoring
    netguard hosts | alerts        inspect the database
    netguard trust/untrust/forget  manage devices
    netguard report -o r.html      HTML security report
    netguard incidents             correlated incidents (alerts grouped into cases)
    netguard pcap FILE             run the detections over a packet capture
    netguard simulate / validate   build attack pcaps / prove every detection fires
    netguard export --format ecs   alert history for a SIEM (json, ecs, cef)
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
from .notify import COLORS, RESET, Notifier, build_sinks, format_alert, is_tty
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
    sub = parser.add_subparsers(dest="command")

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

    p = sub.add_parser("incidents", help="Show correlated incidents")
    p.add_argument("-d", "--days", type=int, default=30)
    p.add_argument("--all", action="store_true", help="Include closed incidents")
    p.add_argument("--show", metavar="ID", help="Print one incident as a Markdown report")

    p = sub.add_parser("pcap", help="Run the live detectors over a .pcap/.pcapng file")
    p.add_argument("file", type=Path)
    p.add_argument("--gateway", help="Gateway IP (default: learned from DHCP in the capture)")
    p.add_argument("--gateway-mac", help="Known-good gateway MAC (default: first ARP claim)")
    p.add_argument("--baseline", action="store_true",
                   help="Use the database's baseline (gateway + known IP/MAC bindings)")
    p.add_argument("--import", dest="do_import", action="store_true",
                   help="Store the alerts in the database (they appear in the dashboard)")
    p.add_argument("--json", action="store_true", help="Machine-readable output")

    p = sub.add_parser("simulate", help="Write attack-simulation captures (.pcap)")
    p.add_argument("-o", "--out", type=Path, default=Path("samples"))
    p.add_argument("--scenario", help="Only this scenario")

    p = sub.add_parser("validate", help="Replay every attack simulation; fail if a detection misses")
    p.add_argument("-v", "--verbose", dest="detail", action="store_true", help="Show each alert")

    p = sub.add_parser("export", help="Export alert history for a SIEM")
    p.add_argument("--format", choices=["json", "ecs", "cef"], default="ecs")
    p.add_argument("-d", "--days", type=int, default=30)
    p.add_argument("-o", "--output", type=Path, help="File (default: stdout)")

    sub.add_parser("test-notify", help="Send a test alert to every configured sink")

    p = sub.add_parser("stop", help="Stop a running NetGuard dashboard")
    p.add_argument("--port", type=int, help="Port it runs on (default 8000)")

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
    notifier = Notifier(store, build_sinks(cfg.notify, cfg.alerts.log, cfg.alerts.log_format),
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
          reload=args.reload, reuse_existing=monitor is not None)


def cmd_stop(store: Store, args, cfg: Config) -> None:
    from .web.server import running_netguard, stop_running
    port = args.port or cfg.web.port
    if running_netguard(port, cfg.web.token) is None:
        sys.exit(f"No NetGuard is running on port {port}.")
    if not stop_running(port, cfg.web.token):
        sys.exit(f"NetGuard on port {port} refused to stop (wrong or missing token?).")
    print(f"Stopped NetGuard on port {port}.")


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
    sinks = build_sinks(cfg.notify, cfg.alerts.log, cfg.alerts.log_format)
    if not sinks:
        sys.exit("No [[notify]] sinks configured in netguard.toml")
    notifier = Notifier(store, sinks, suppress_minutes=0)
    notifier.emit(Alert(Severity.CRITICAL, "test",
                        "Test alert from NetGuard. If you can read this, notifications work."))
    Notifier._pool.shutdown(wait=True)
    print(f"Sent to {len(sinks)} sink(s): {', '.join(type(s).__name__ for s in sinks)}")


def cmd_incidents(store: Store, args, cfg: Config) -> None:
    from .correlate import find
    from .incidents import incident_markdown, load_incidents
    incidents = load_incidents(store, args.days)
    if args.show:
        inc = find(incidents, args.show)
        if inc is None:
            sys.exit(f"No incident {args.show} in the last {args.days} days")
        print(incident_markdown(store, inc))
        return
    shown = incidents if args.all else [i for i in incidents if i.is_open]
    if not shown:
        print("No open incidents." if not args.all else "No incidents.")
        return
    color = is_tty()
    for i in shown:
        sev = f"[{i.severity.name:<8}]"
        if color:
            sev = f"{COLORS[i.severity]}{sev}{RESET}"
        who = i.name or i.ip or i.mac
        print(f"{i.id}  {sev} {i.status:<14} {i.pattern.title}")
        print(f"          {who}  ·  {len(i.alerts)} alerts  ·  {' → '.join(i.tactics) or '-'}")
    print(f"\n{len(shown)} incident(s). Details: netguard incidents --show <ID>")


def cmd_pcap(store: Store, args, cfg: Config) -> None:
    from . import pcap
    kw: dict = {"gateway_ip": args.gateway or "", "gateway_mac": (
        discovery.normalize_mac(args.gateway_mac) if args.gateway_mac else ""),
        "scan_threshold": cfg.sniff.port_scan_threshold, "scan_window": cfg.sniff.port_scan_window,
        "dhcp_servers": cfg.sniff.dhcp_servers}
    if args.baseline:
        from .detect import GATEWAY_IP_KEY, GATEWAY_MAC_KEY
        kw["known"] = {h.ip: h.mac for h in store.all_hosts() if h.ip}
        kw["gateway_ip"] = kw["gateway_ip"] or store.get_meta(GATEWAY_IP_KEY) or ""
        kw["gateway_mac"] = kw["gateway_mac"] or store.get_meta(GATEWAY_MAC_KEY) or ""
    try:
        result = pcap.analyze(args.file, **kw)
    except (OSError, pcap.CaptureError) as exc:
        sys.exit(f"Can't read {args.file}: {exc}")

    if args.do_import:
        for a in result.alerts:
            if store.match_suppression(a) is not None:
                a.status = "suppressed"
            store.add_alert(a)
    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
        return
    print_analysis(result, store if args.baseline else None)
    if args.do_import:
        print(f"\nImported {len(result.alerts)} alert(s) into {args.db}.")


def print_analysis(result, store: Store | None = None) -> None:
    from .pcap import iso
    color = is_tty()
    dur = result.last_ts - result.first_ts
    protos = " · ".join(f"{k} {v:,}" for k, v in result.protocols.most_common())
    print(f"Capture    {result.source}")
    print(f"Packets    {result.packets:,} over {dur:,.1f}s  ({iso(result.first_ts)} → {iso(result.last_ts)})")
    print(f"Protocols  {protos}")
    if result.gateway_ip:
        print(f"Gateway    {result.gateway_ip} is-at {result.gateway_mac or '?'}"
              f"  (from {result.gateway_source or 'argument'})")
    for s in result.dhcp_servers:
        print(f"DHCP       server {s['server_ip']} ({s['server_mac']}) router {s['router'] or '?'}"
              f" dns {s['dns'] or '?'}  first frame {s['first_frame']}")
    from .pcap import ip_conflicts
    known = {h.mac for h in store.all_hosts()} if store else set()
    conflicts = ip_conflicts(result.hosts)
    print(f"\nHosts ({len(result.hosts)})")
    print(f"  {'MAC':<18} {'VENDOR':<16} {'FRAMES':>6}  {'FIRST':<7} IPv4")
    for h in sorted(result.hosts.values(), key=lambda h: h.first_frame):
        vendor = discovery.lookup_vendor(h.mac) or ""
        flags = []
        if store and h.mac not in known:
            flags.append("NOT IN BASELINE")
        flags += [f"CLAIMS {ip} (also {', '.join(m for m in conflicts[ip] if m != h.mac)})"
                  for ip in sorted(h.ips) if ip in conflicts]
        print(f"  {h.mac:<18} {vendor[:16]:<16} {h.frames:>6}  #{h.first_frame:<6} "
              f"{', '.join(sorted(h.ips)) or '-'}" + "".join(f"  <- {f}" for f in flags))
    print(f"\nAlerts ({len(result.alerts)})")
    for a in result.alerts:
        line = format_alert(a, color)
        print(f"  {line}  [frame {a.details.get('frame')}]")
    if not result.alerts:
        print("  none")


def cmd_simulate(store: Store, args, cfg: Config) -> None:
    from .simulate import SCENARIOS, scenario, write_pcap
    chosen = [scenario(args.scenario)] if args.scenario else SCENARIOS
    args.out.mkdir(parents=True, exist_ok=True)
    for s in chosen:
        path = args.out / f"{s.name}.pcap"
        write_pcap(path, s.build())
        print(f"{str(path):<44} {s.technique or 'benign':<10} {s.title}")


def cmd_validate(store: Store, args, cfg: Config) -> None:
    from .simulate import validate_all
    color = is_tty()
    green, red, dim, reset = ("\033[32m", "\033[31m", "\033[2m", "\033[0m") if color else ("",) * 4
    results = validate_all()
    print(f"Detection validation: {len(results)} scenarios replayed through the live detectors\n")
    print(f"  {'RESULT':<6}  {'SCENARIO':<27} {'ATT&CK':<10} EXPECTATION")
    for r in results:
        s = r.scenario
        mark = f"{green}PASS{reset}" if r.passed else f"{red}FAIL{reset}"
        if s.expect - {"dhcp_server_learned"}:
            want = "fires " + ", ".join(sorted(s.expect - {"dhcp_server_learned"}))
        elif "*" in s.forbid:
            want = "no alerts (false-positive check)"
        else:
            want = "silent: " + ", ".join(sorted(s.forbid)) + (" (known gap)" if s.gap else "")
        print(f"  {mark}    {s.name:<27} {s.technique or '-':<10} {want}")
        if r.missing:
            print(f"          {red}missing: {', '.join(sorted(r.missing))}{reset}")
        if r.unexpected:
            print(f"          {red}unexpected: {', '.join(sorted(r.unexpected))}{reset}")
        if args.detail:
            for a in r.analysis.alerts:
                print(f"          {dim}frame {a.details['frame']:<4} {a.severity.name:<8} {a.message}{reset}")
    passed = sum(r.passed for r in results)
    print(f"\n{passed}/{len(results)} passed")
    if passed != len(results):
        sys.exit(1)


def cmd_export(store: Store, args, cfg: Config) -> None:
    from .siem import format_alert as siem_format
    from .store import iso_ago
    alerts = store.recent_alerts(limit=100000, since=iso_ago(days=args.days), statuses=None)
    lines = [siem_format(a, args.format) for a in reversed(alerts)]
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {len(lines)} alert(s) as {args.format.upper()} to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


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
    "incidents": cmd_incidents, "pcap": cmd_pcap, "simulate": cmd_simulate,
    "validate": cmd_validate, "export": cmd_export, "stop": cmd_stop,
}

QUICK_START = f"""NetGuard {__version__}: network intrusion detection and SOC console

  python -m netguard demo                try the dashboard on a fictional network
  python -m netguard serve --open        monitor your own network (first scan = baseline)
  python -m netguard stop                stop a running dashboard (or use its Stop button)
  python -m netguard validate            prove every detection fires on simulated attacks
  python -m netguard pcap FILE           analyze a packet capture

On Windows you can also just double-click NetGuard.bat.
All commands: python -m netguard --help"""


# --- Entry point ------------------------------------------------------------
def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command is None:
        print(QUICK_START)
        return
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
