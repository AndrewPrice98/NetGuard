"""
A fictional network for demos and screenshots.

`netguard demo` builds this into its own database and opens the dashboard
in view-only mode, so people can try NetGuard (and you can take screenshots)
without scanning, or publishing, a real network.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import re
from pathlib import Path

from .models import Alert, Event, Host, PortState, Severity
from .portscan import COMMON_PORTS
from .store import Store, iso_ago

# (ip, mac, hostname, vendor, type, ports, trusted, first seen hours ago)
DEVICES = [
    ("192.168.1.1", "f0:9f:c2:10:20:01", "gateway.lan", "Ubiquiti", "router", [53, 80, 443], True, 900),
    ("192.168.1.10", "00:11:32:aa:01:02", "diskstation", "Synology", "nas", [80, 443, 445, 5000], True, 900),
    ("192.168.1.12", "3c:2a:f4:51:7e:90", "BRW3C2AF4", "Brother", "printer", [80, 9100], True, 900),
    ("192.168.1.20", "a4:83:e7:2b:11:5c", "alex-macbook", "Apple", "computer", [22], True, 900),
    ("192.168.1.21", "7c:ed:8d:40:8e:12", "DESKTOP-GAMING", "Microsoft", "computer", [135, 139, 445], True, 900),
    ("192.168.1.30", "8c:85:90:6a:c3:01", "alexs-iphone", "Apple", "phone", [], True, 900),
    ("192.168.1.31", "1e:ee:3b:01:45:85", "", "randomized MAC", "mobile", [], True, 900),
    ("192.168.1.40", "44:65:0d:c0:ff:ee", "echo-kitchen", "Amazon", "speaker", [], True, 900),
    ("192.168.1.41", "f4:f5:d8:9a:aa:10", "living-room-tv", "Google", "tv", [8008, 8443], True, 900),
    ("192.168.1.50", "ec:fa:bc:12:34:56", "shelly-plug-1", "Espressif", "iot", [80], True, 900),
    ("192.168.1.51", "00:17:88:0b:ad:00", "philips-hue", "Philips Hue", "iot", [80, 443], True, 900),
    ("192.168.1.60", "dc:a6:32:7f:00:01", "pihole", "Raspberry Pi", "sbc", [22, 53, 80], True, 900),
    ("192.168.1.61", "a8:8c:3e:97:68:65", "XBOX", "Microsoft", "console", [], True, 900),
    # The interesting ones: joined after the baseline.
    ("192.168.1.87", "de:ad:be:ef:13:37", "kali", "randomized MAC", "mobile", [22, 4444], False, 3),
    ("192.168.1.92", "b8:27:eb:66:66:66", "raspberrypi", "Raspberry Pi", "sbc", [22, 80, 3389], False, 30),
]

# (hours ago, severity, kind, message, acked)
ALERTS = [
    (0.1, Severity.CRITICAL, "gateway_arp_spoof",
     "Live ARP traffic claims gateway 192.168.1.1 is at de:ad:be:ef:13:37 "
     "(expected f0:9f:c2:10:20:01). Man-in-the-middle in progress?", False),
    (0.2, Severity.HIGH, "port_scan", "192.168.1.87 probed 214 ports in 10s", False),
    (0.3, Severity.HIGH, "new_port", "192.168.1.87 de:ad:be:ef:13:37 kali opened tcp/4444 (metasploit)", False),
    (3, Severity.MEDIUM, "new_host",
     "New device on the network: 192.168.1.87 de:ad:be:ef:13:37 kali (randomized MAC)", False),
    (20, Severity.HIGH, "new_port",
     "192.168.1.92 b8:27:eb:66:66:66 raspberrypi (Raspberry Pi) opened tcp/3389 (rdp)", False),
    (30, Severity.MEDIUM, "new_host",
     "New device on the network: 192.168.1.92 b8:27:eb:66:66:66 raspberrypi (Raspberry Pi)", True),
    (52, Severity.LOW, "ip_changed_hands",
     "192.168.1.31 moved from 1e:ee:3b:01:45:84 to 1e:ee:3b:01:45:85", True),
    (75, Severity.INFO, "dhcp_server_learned", "Trusting DHCP server 192.168.1.1 (f0:9f:c2:10:20:01)", True),
]


# Older background noise so the 14-day chart has history: (days ago, severity, kind, message, status)
HISTORY = [
    (2, Severity.LOW, "ip_changed_hands", "192.168.1.31 moved from 1e:ee:3b:01:45:80 to 1e:ee:3b:01:45:84", "resolved"),
    (4, Severity.MEDIUM, "new_host", "New device on the network: 192.168.1.77 3a:aa:bb:cc:dd:01 (randomized MAC)", "resolved"),
    (5, Severity.MEDIUM, "duplicate_mac", "MAC f0:9f:c2:10:20:01 answers for multiple IPs: 192.168.1.1, 192.168.1.2", "suppressed"),
    (6, Severity.MEDIUM, "duplicate_mac", "MAC f0:9f:c2:10:20:01 answers for multiple IPs: 192.168.1.1, 192.168.1.2", "suppressed"),
    (7, Severity.HIGH, "new_port", "192.168.1.21 7c:ed:8d:40:8e:12 DESKTOP-GAMING (Microsoft) opened tcp/445 (smb)", "false_positive"),
    (9, Severity.MEDIUM, "new_host", "New device on the network: 192.168.1.41 f4:f5:d8:9a:aa:10 living-room-tv (Google)", "resolved"),
    (11, Severity.LOW, "ip_changed_hands", "192.168.1.30 moved from 8c:85:90:6a:c3:00 to 8c:85:90:6a:c3:01", "resolved"),
    (12, Severity.HIGH, "port_scan", "192.168.1.60 probed 48 ports in 10s", "false_positive"),
]

ALIASES = {
    "a4:83:e7:2b:11:5c": ("Alex's MacBook", "Work laptop. Owner: Alex."),
    "7c:ed:8d:40:8e:12": ("Gaming PC", "Den. RDP intentionally disabled."),
    "dc:a6:32:7f:00:01": ("Pi-hole DNS", "Network-wide ad blocker; runs the weekly nmap audit."),
    "00:11:32:aa:01:02": ("NAS", "Backups. SMB is expected."),
}
OFFLINE = {"f4:f5:d8:9a:aa:10", "1e:ee:3b:01:45:85"}

EVENTS = [  # (hours ago, kind, mac, ip, message)
    (0.05, "port_open", "de:ad:be:ef:13:37", "192.168.1.87", "kali: port 4444 opened"),
    (3, "first_seen", "de:ad:be:ef:13:37", "192.168.1.87", "First seen: 192.168.1.87 de:ad:be:ef:13:37 kali (randomized MAC)"),
    (5, "offline", "f4:f5:d8:9a:aa:10", "192.168.1.41", "living-room-tv went offline (last at 192.168.1.41)"),
    (8, "offline", "1e:ee:3b:01:45:85", "192.168.1.31", "1e:ee:3b:01:45:85 went offline (last at 192.168.1.31)"),
    (20, "port_open", "b8:27:eb:66:66:66", "192.168.1.92", "raspberrypi: port 3389 opened"),
    (30, "first_seen", "b8:27:eb:66:66:66", "192.168.1.92", "First seen: 192.168.1.92 b8:27:eb:66:66:66 raspberrypi (Raspberry Pi)"),
    (31, "online", "a4:83:e7:2b:11:5c", "192.168.1.20", "Alex's MacBook came online at 192.168.1.20"),
    (44, "ip_change", "8c:85:90:6a:c3:01", "192.168.1.30", "alexs-iphone moved 192.168.1.33 → 192.168.1.30"),
    (50, "offline", "a4:83:e7:2b:11:5c", "192.168.1.20", "Alex's MacBook went offline (last at 192.168.1.20)"),
    (52, "ip_change", "1e:ee:3b:01:45:85", "192.168.1.31", "1e:ee:3b:01:45:85 moved 192.168.1.35 → 192.168.1.31"),
    (70, "port_closed", "7c:ed:8d:40:8e:12", "192.168.1.21", "Gaming PC: port 3389 closed"),
]


def _details(message: str) -> dict:
    """Link a demo alert to its device, the way real detectors fill `details`."""
    macs = re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", message)
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", message)
    by_ip = {d[0]: d[1] for d in DEVICES}
    ip = next((i for i in ips if i != "192.168.1.1"), ips[0] if ips else "")
    mac = macs[0] if macs else by_ip.get(ip, "")
    return {"mac": mac, "ip": ip} if mac or ip else {}


def build_demo_db(path: Path) -> Path:
    """(Re)create the demo database at `path`."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)

    with Store(path) as s:
        s.set_meta("baseline_at", iso_ago(hours=899))
        s.set_meta("gateway_ip", "192.168.1.1")
        s.set_meta("gateway_mac", "f0:9f:c2:10:20:01")
        for ip, mac, name, vendor, dtype, ports, trusted, hours in DEVICES:
            alias, notes = ALIASES.get(mac, ("", ""))
            s.upsert_host(Host(mac=mac, ip=ip, hostname=name, vendor=vendor,
                               first_seen=iso_ago(hours=hours), last_seen=iso_ago(minutes=2),
                               trusted=trusted, device_type=dtype, alias=alias, notes=notes))
            s.record_ports(mac, [PortState(mac, p, service=COMMON_PORTS.get(p, ""))
                                 for p in ports])
            if mac in OFFLINE:
                s.set_online(mac, False)

        for days, sev, kind, message, status in HISTORY:
            alert = Alert(sev, kind, message, iso_ago(days=days), _details(message))
            s.add_alert(alert)
            s.set_alert_status(alert.id, status)
        for hours, sev, kind, message, acked in reversed(ALERTS):
            alert = Alert(sev, kind, message, iso_ago(hours=hours), _details(message))
            s.add_alert(alert)
            if acked:
                s.ack_alert(alert.id)
            elif kind == "port_scan":
                s.set_alert_status(alert.id, "investigating",
                                   "Source is the unknown 'kali' host. Not our audit scanner.")

        for hours, kind, mac, ip, message in reversed(EVENTS):
            s.add_event(Event(kind, message, mac, ip, ts=iso_ago(hours=hours)))

        s.add_suppression("duplicate_mac", "f0:9f:c2:10:20:01", "",
                          "Router legitimately answers for its management IP")
        s.add_suppression("port_scan", "", "192.168.1.60", "Pi-hole runs the weekly nmap audit")
    return path
