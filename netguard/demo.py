"""
A fictional network for demos and screenshots.

`netguard demo` builds this into its own database and opens the dashboard
in view-only mode, so people can try NetGuard (and you can take screenshots)
without scanning, or publishing, a real network.

The story the data tells:

  * INC (active): an unknown laptop calling itself "kali" joined three hours
    ago, port-scanned the network, opened a listener on tcp/4444, and is now
    ARP-spoofing the gateway. Four alerts, one adversary-in-the-middle chain.
    The capture of this attack is `samples/mitm_kill_chain.pcap`.
  * INC (open): a Raspberry Pi nobody has claimed is exposing RDP.
  * Closed cases from the past two weeks, both real (a TV box shipping with
    telnet enabled) and false positives (the Pi-hole's weekly nmap audit),
    each with a triage history, so the response-time metrics are realistic.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

from pathlib import Path

from .models import Alert, Event, Host, PortState, Severity
from .portscan import COMMON_PORTS
from .store import Store, iso_ago

GW_IP, GW_MAC = "192.168.1.1", "f0:9f:c2:10:20:01"
KALI_IP, KALI_MAC = "192.168.1.87", "de:ad:be:ef:13:37"
PI_IP, PI_MAC = "192.168.1.92", "b8:27:eb:66:66:66"
BOX_IP, BOX_MAC = "192.168.1.45", "a0:d0:5b:3e:91:7c"

# (ip, mac, hostname, vendor, type, ports, trusted, first seen hours ago)
DEVICES = [
    (GW_IP, GW_MAC, "gateway.lan", "Ubiquiti", "router", [53, 80, 443], True, 900),
    ("192.168.1.10", "00:11:32:aa:01:02", "diskstation", "Synology", "nas", [80, 443, 445, 5000], True, 900),
    ("192.168.1.12", "3c:2a:f4:51:7e:90", "BRW3C2AF4", "Brother", "printer", [80, 9100], True, 900),
    ("192.168.1.20", "a4:83:e7:2b:11:5c", "alex-macbook", "Apple", "computer", [22], True, 900),
    ("192.168.1.21", "7c:ed:8d:40:8e:12", "DESKTOP-GAMING", "Microsoft", "computer", [135, 139, 445], True, 900),
    ("192.168.1.30", "8c:85:90:6a:c3:01", "alexs-iphone", "Apple", "phone", [], True, 900),
    ("192.168.1.31", "1e:ee:3b:01:45:85", "", "randomized MAC", "mobile", [], True, 900),
    ("192.168.1.40", "44:65:0d:c0:ff:ee", "echo-kitchen", "Amazon", "speaker", [], True, 900),
    ("192.168.1.41", "f4:f5:d8:9a:aa:10", "living-room-tv", "Google", "tv", [8008, 8443], True, 900),
    (BOX_IP, BOX_MAC, "android-tvbox", "Amlogic", "tv", [8008], True, 200),
    ("192.168.1.50", "ec:fa:bc:12:34:56", "shelly-plug-1", "Espressif", "iot", [80], True, 900),
    ("192.168.1.51", "00:17:88:0b:ad:00", "philips-hue", "Philips Hue", "iot", [80, 443], True, 900),
    ("192.168.1.60", "dc:a6:32:7f:00:01", "pihole", "Raspberry Pi", "sbc", [22, 53, 80], True, 900),
    ("192.168.1.61", "a8:8c:3e:97:68:65", "XBOX", "Microsoft", "console", [], True, 900),
    # Joined after the baseline and still unexplained.
    (KALI_IP, KALI_MAC, "kali", "randomized MAC", "computer", [22, 4444], False, 3),
    (PI_IP, PI_MAC, "raspberrypi", "Raspberry Pi", "sbc", [22, 80, 3389], False, 30),
]

ALIASES = {
    "a4:83:e7:2b:11:5c": ("Alex's MacBook", "Work laptop. Owner: Alex."),
    "7c:ed:8d:40:8e:12": ("Gaming PC", "Den. RDP intentionally disabled."),
    "dc:a6:32:7f:00:01": ("Pi-hole DNS", "Network-wide ad blocker; runs the weekly nmap audit."),
    "00:11:32:aa:01:02": ("NAS", "Backups. SMB is expected."),
    BOX_MAC: ("Kids' TV box", "Cheap Android box. Shipped with telnet on; fixed by firmware 2.1."),
}
OFFLINE = {"f4:f5:d8:9a:aa:10", "1e:ee:3b:01:45:85"}

M = 1 / 60  # one minute, in hours

# Every alert: (hours ago, severity, kind, message, details, triage)
# triage: list of (minutes after the alert, new status, note)
ALERTS = [
    # --- Active incident: adversary-in-the-middle chain from "kali" --------
    (3.0, Severity.MEDIUM, "new_host",
     f"New device on the network: {KALI_IP} {KALI_MAC} kali (randomized MAC)",
     {"mac": KALI_MAC, "ip": KALI_IP, "hostname": "kali", "vendor": "randomized MAC"},
     [(11, "investigating", "Hostname 'kali' and randomized MAC. Nobody in the household owns it.")]),
    (2.6, Severity.HIGH, "port_scan", f"{KALI_IP} probed 15 ports in 10s",
     {"src": KALI_IP, "ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995]},
     [(9, "investigating", "Source is the unknown 'kali' host, not the Pi-hole audit scanner.")]),
    (1.2, Severity.HIGH, "new_port", f"{KALI_IP} {KALI_MAC} kali opened tcp/4444 (metasploit)",
     {"mac": KALI_MAC, "ip": KALI_IP, "port": 4444, "proto": "tcp", "service": "metasploit"}, []),
    (0.1, Severity.CRITICAL, "gateway_arp_spoof",
     f"Live ARP traffic claims gateway {GW_IP} is at {KALI_MAC} "
     f"(expected {GW_MAC}). Man-in-the-middle in progress?",
     {"ip": GW_IP, "claimed_mac": KALI_MAC, "expected_mac": GW_MAC}, []),

    # --- Open: unclaimed Raspberry Pi exposing RDP --------------------------
    (30, Severity.MEDIUM, "new_host",
     f"New device on the network: {PI_IP} {PI_MAC} raspberrypi (Raspberry Pi)",
     {"mac": PI_MAC, "ip": PI_IP, "hostname": "raspberrypi", "vendor": "Raspberry Pi"},
     [(18, "investigating", "Asked the household who added a Pi.")]),
    (20, Severity.HIGH, "new_port",
     f"{PI_IP} {PI_MAC} raspberrypi (Raspberry Pi) opened tcp/3389 (rdp)",
     {"mac": PI_MAC, "ip": PI_IP, "port": 3389, "proto": "tcp", "service": "rdp"}, []),

    # --- Context ---------------------------------------------------------------
    (52, Severity.LOW, "ip_changed_hands", "192.168.1.31 moved from 1e:ee:3b:01:45:84 to 1e:ee:3b:01:45:85",
     {"ip": "192.168.1.31", "old_mac": "1e:ee:3b:01:45:84", "new_mac": "1e:ee:3b:01:45:85"},
     [(34, "resolved", "Private Wi-Fi address rotation on Alex's iPad.")]),
    (75, Severity.INFO, "dhcp_server_learned", f"Trusting DHCP server {GW_IP} ({GW_MAC})",
     {"server_ip": GW_IP, "server_mac": GW_MAC}, [(5, "resolved", "")]),

    # --- Closed cases (history) ---------------------------------------------
    (24 * 2, Severity.LOW, "ip_changed_hands", "192.168.1.31 moved from 1e:ee:3b:01:45:80 to 1e:ee:3b:01:45:84",
     {"ip": "192.168.1.31", "old_mac": "1e:ee:3b:01:45:80", "new_mac": "1e:ee:3b:01:45:84"},
     [(26, "resolved", "MAC rotation again.")]),
    (24 * 4, Severity.MEDIUM, "new_host",
     "New device on the network: 192.168.1.77 3a:aa:bb:cc:dd:01 (randomized MAC)",
     {"mac": "3a:aa:bb:cc:dd:01", "ip": "192.168.1.77", "vendor": "randomized MAC"},
     [(14, "investigating", ""), (95, "resolved", "Guest's phone (Sam). Left the same evening.")]),
    (24 * 5, Severity.MEDIUM, "duplicate_mac", f"MAC {GW_MAC} answers for multiple IPs: {GW_IP}, 192.168.1.2",
     {"mac": GW_MAC, "ips": [GW_IP, "192.168.1.2"]}, "suppressed"),
    (24 * 6, Severity.MEDIUM, "duplicate_mac", f"MAC {GW_MAC} answers for multiple IPs: {GW_IP}, 192.168.1.2",
     {"mac": GW_MAC, "ips": [GW_IP, "192.168.1.2"]}, "suppressed"),
    (24 * 7, Severity.HIGH, "new_port",
     "192.168.1.21 7c:ed:8d:40:8e:12 DESKTOP-GAMING (Microsoft) opened tcp/445 (smb)",
     {"mac": "7c:ed:8d:40:8e:12", "ip": "192.168.1.21", "port": 445, "proto": "tcp", "service": "smb"},
     [(22, "investigating", ""), (41, "false_positive", "Windows update re-enabled file sharing. Expected.")]),
    (24 * 8 + 3, Severity.MEDIUM, "new_host",
     f"New device on the network: {BOX_IP} {BOX_MAC} android-tvbox (Amlogic)",
     {"mac": BOX_MAC, "ip": BOX_IP, "hostname": "android-tvbox", "vendor": "Amlogic"},
     [(7, "investigating", "Kids' new TV box."),
      (215, "resolved", "Owner confirmed. Trusted once telnet was disabled (see new_port alert).")]),
    (24 * 8 + 2.5, Severity.HIGH, "new_port",
     f"{BOX_IP} {BOX_MAC} android-tvbox (Amlogic) opened tcp/23 (telnet)",
     {"mac": BOX_MAC, "ip": BOX_IP, "port": 23, "proto": "tcp", "service": "telnet"},
     [(12, "investigating", "Telnet with default root password, confirmed from the NAS."),
      (190, "resolved", "Flashed vendor firmware 2.1 that disables telnet; port closed. Device trusted.")]),
    (24 * 9, Severity.MEDIUM, "new_host",
     "New device on the network: 192.168.1.41 f4:f5:d8:9a:aa:10 living-room-tv (Google)",
     {"mac": "f4:f5:d8:9a:aa:10", "ip": "192.168.1.41", "hostname": "living-room-tv", "vendor": "Google"},
     [(31, "resolved", "New Chromecast in the living room.")]),
    (24 * 11, Severity.LOW, "ip_changed_hands", "192.168.1.30 moved from 8c:85:90:6a:c3:00 to 8c:85:90:6a:c3:01",
     {"ip": "192.168.1.30", "old_mac": "8c:85:90:6a:c3:00", "new_mac": "8c:85:90:6a:c3:01"},
     [(48, "resolved", "")]),
    (24 * 12, Severity.HIGH, "port_scan", "192.168.1.60 probed 15 ports in 10s",
     {"src": "192.168.1.60", "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080]},
     [(6, "investigating", ""), (9, "false_positive",
                                 "Weekly nmap audit from the Pi-hole. Suppression rule added.")]),
]

EVENTS = [  # (hours ago, kind, mac, ip, message)
    (1.2, "port_open", KALI_MAC, KALI_IP, "kali: port 4444 opened"),
    (3, "first_seen", KALI_MAC, KALI_IP, f"First seen: {KALI_IP} {KALI_MAC} kali (randomized MAC)"),
    (5, "offline", "f4:f5:d8:9a:aa:10", "192.168.1.41", "living-room-tv went offline (last at 192.168.1.41)"),
    (8, "offline", "1e:ee:3b:01:45:85", "192.168.1.31", "1e:ee:3b:01:45:85 went offline (last at 192.168.1.31)"),
    (20, "port_open", PI_MAC, PI_IP, "raspberrypi: port 3389 opened"),
    (30, "first_seen", PI_MAC, PI_IP, f"First seen: {PI_IP} {PI_MAC} raspberrypi (Raspberry Pi)"),
    (31, "online", "a4:83:e7:2b:11:5c", "192.168.1.20", "Alex's MacBook came online at 192.168.1.20"),
    (44, "ip_change", "8c:85:90:6a:c3:01", "192.168.1.30", "alexs-iphone moved 192.168.1.33 → 192.168.1.30"),
    (50, "offline", "a4:83:e7:2b:11:5c", "192.168.1.20", "Alex's MacBook went offline (last at 192.168.1.20)"),
    (52, "ip_change", "1e:ee:3b:01:45:85", "192.168.1.31", "1e:ee:3b:01:45:85 moved 192.168.1.35 → 192.168.1.31"),
    (70, "port_closed", "7c:ed:8d:40:8e:12", "192.168.1.21", "Gaming PC: port 3389 closed"),
    (24 * 8 - 1, "port_closed", BOX_MAC, BOX_IP, "Kids' TV box: port 23 closed"),
    (24 * 8 + 2.5, "port_open", BOX_MAC, BOX_IP, "android-tvbox: port 23 opened"),
    (24 * 8 + 3, "first_seen", BOX_MAC, BOX_IP, f"First seen: {BOX_IP} {BOX_MAC} android-tvbox (Amlogic)"),
]


def build_demo_db(path: Path) -> Path:
    """(Re)create the demo database at `path`."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)

    with Store(path) as s:
        s.set_meta("baseline_at", iso_ago(hours=899))
        s.set_meta("gateway_ip", GW_IP)
        s.set_meta("gateway_mac", GW_MAC)
        for ip, mac, name, vendor, dtype, ports, trusted, hours in DEVICES:
            alias, notes = ALIASES.get(mac, ("", ""))
            s.upsert_host(Host(mac=mac, ip=ip, hostname=name, vendor=vendor,
                               first_seen=iso_ago(hours=hours), last_seen=iso_ago(minutes=2),
                               trusted=trusted, device_type=dtype, alias=alias, notes=notes))
            s.record_ports(mac, [PortState(mac, p, service=COMMON_PORTS.get(p, ""))
                                 for p in ports])
            if mac in OFFLINE:
                s.set_online(mac, False)
        # The TV box's telnet port: seen once, closed since the firmware fix.
        s.conn.execute("INSERT INTO ports (mac, port, proto, service, first_seen, last_seen)"
                       " VALUES (?, 23, 'tcp', 'telnet', ?, ?)",
                       (BOX_MAC, iso_ago(hours=24 * 8 + 2.5), iso_ago(hours=24 * 8 - 1)))
        s.conn.commit()

        # Oldest first, so alert IDs (and incident IDs) follow time.
        for hours, sev, kind, message, details, triage in sorted(ALERTS, key=lambda a: -a[0]):
            alert = Alert(sev, kind, message, iso_ago(hours=hours), dict(details))
            if triage == "suppressed":
                alert.status = "suppressed"
                triage = []
            s.add_alert(alert)
            for minutes, status, note in triage:
                s.set_alert_status(alert.id, status, note, ts=iso_ago(hours=hours - minutes * M))

        for hours, kind, mac, ip, message in sorted(EVENTS, key=lambda e: -e[0]):
            s.add_event(Event(kind, message, mac, ip, ts=iso_ago(hours=hours)))

        s.add_suppression("duplicate_mac", GW_MAC, "",
                          "Router legitimately answers for its management IP")
        s.add_suppression("port_scan", "", "192.168.1.60", "Pi-hole runs the weekly nmap audit")
    return path
