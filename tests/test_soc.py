"""Analyst-workflow features: triage, notes, suppression, events, stats, export."""

import csv
import io
import json
import threading

import pytest

from netguard.config import Config
from netguard.engine import Monitor
from netguard.models import Alert, Host, PortState, Severity
from netguard.notify import Notifier
from netguard.playbooks import PLAYBOOKS, playbook
from netguard.store import Store
from netguard.web.server import DashboardServer, risk_factors, risk_score
from tests.test_web import POST, request

MAC, IP = "aa:bb:cc:00:00:01", "10.0.0.50"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def alert(sev=Severity.HIGH, kind="new_port", mac=MAC, ip=IP, msg="opened tcp/3389"):
    return Alert(sev, kind, msg, details={"mac": mac, "ip": ip, "port": 3389})


# --- Triage workflow ----------------------------------------------------------
def test_status_workflow_and_notes(store):
    a = alert()
    store.add_alert(a)
    assert store.get_alert(a.id).status == "new"
    assert store.set_alert_status(a.id, "investigating", "Looking at RDP logs")
    store.add_alert_note(a.id, "Owner confirms they enabled it")
    got = store.get_alert(a.id)
    assert got.status == "investigating" and not got.acked
    assert got.notes.count("\n") == 1 and "RDP logs" in got.notes
    store.set_alert_status(a.id, "resolved")
    assert store.get_alert(a.id).acked
    assert store.status_counts()["resolved"] == 1
    with pytest.raises(ValueError):
        store.set_alert_status(a.id, "deleted")


def test_open_filter_and_search(store):
    for msg in ("first thing", "second thing", "100%_literal"):
        store.add_alert(alert(msg=msg))
    store.set_status_bulk([1], "false_positive")
    assert len(store.recent_alerts(unacked_only=True)) == 2
    assert [a.message for a in store.recent_alerts(query="second")] == ["second thing"]
    assert [a.message for a in store.recent_alerts(query="%_")] == ["100%_literal"]  # LIKE escaped
    assert len(store.recent_alerts(mac=MAC)) == 3 and store.recent_alerts(mac="ff:ff:ff:ff:ff:01") == []


def test_alert_entity_resolution():
    assert Alert(Severity.HIGH, "port_scan", "x", details={"src": "1.2.3.4"}).entity() == ("", "1.2.3.4")
    spoof = Alert(Severity.CRITICAL, "gateway_arp_spoof", "x",
                  details={"ip": "10.0.0.1", "claimed_mac": "de:ad", "expected_mac": "aa"})
    assert spoof.entity() == ("de:ad", "10.0.0.1")


# --- Suppression --------------------------------------------------------------
def test_suppression_records_but_does_not_notify(store):
    store.add_suppression("new_port", MAC, "", "Admin box, RDP expected")
    n = Notifier(store, quiet=True)
    assert n.emit(alert()) is False
    [a] = store.recent_alerts(statuses=["suppressed"])
    assert a.status == "suppressed"
    assert store.suppressions()[0]["hits"] == 1
    # A different device is not covered by the rule.
    assert n.emit(alert(mac="aa:bb:cc:00:00:02", msg="other")) is True


def test_wildcard_and_ip_rules(store):
    store.add_suppression("*", "", "10.0.0.60", "Audit scanner")
    assert store.match_suppression(Alert(Severity.HIGH, "port_scan", "x", details={"src": "10.0.0.60"}))
    assert store.match_suppression(Alert(Severity.HIGH, "port_scan", "x", details={"src": "10.0.0.61"})) is None


# --- Statistics ---------------------------------------------------------------
def test_alert_series_and_top_lists(store):
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.HIGH):
        store.add_alert(alert(sev=sev, msg=str(sev)))
    series = store.alert_series(7)
    assert len(series) == 7 and series[-1]["HIGH"] == 2 and series[-1]["CRITICAL"] == 1
    assert series[0]["HIGH"] == 0
    assert store.top_kinds(7)[0] == {"kind": "new_port", "count": 3, "severity": "CRITICAL"}
    assert store.top_devices(7) == [{"mac": MAC, "count": 3, "severity": "CRITICAL"}]


# --- Presence & port events ---------------------------------------------------
def test_engine_records_presence_and_port_events(store):
    old = Host(mac=MAC, ip=IP, hostname="laptop", trusted=True)
    gone = Host(mac="aa:bb:cc:00:00:02", ip="10.0.0.51", trusted=True)
    store.upsert_host(old)
    store.upsert_host(gone)
    before = {h.mac: h for h in store.all_hosts()}
    store.set_online(MAC, False)
    before[MAC].online = False

    moved = Host(mac=MAC, ip="10.0.0.99")
    new = Host(mac="aa:bb:cc:00:00:03", ip="10.0.0.52")
    Monitor._record_presence(store, before, [moved, new])
    Monitor._record_port_changes(store, moved, {80, 22}, {80, 3389})

    kinds = sorted(e.kind for e in store.events())
    assert kinds == ["first_seen", "ip_change", "offline", "online", "port_closed", "port_open"]
    assert not store.get_host("aa:bb:cc:00:00:02").online
    assert store.events(mac=MAC, kind="ip_change")[0].details == {"old_ip": IP, "new_ip": "10.0.0.99"}


def test_open_ports_tracks_latest_check(store):
    store.record_ports(MAC, [PortState(MAC, 22), PortState(MAC, 80)])
    store.conn.execute("UPDATE ports SET last_seen = '2000-01-01' WHERE port = 22")
    store.conn.commit()
    assert [p.port for p in store.open_ports()[MAC]] == [80]
    assert [p.port for p in store.all_ports()[MAC]] == [22, 80]


def test_port_survives_one_missed_check(store, monkeypatch):
    """Sleepy printers miss probes; a port only 'closes' after two misses."""
    import netguard.store as store_mod

    def check(ts, ports):
        monkeypatch.setattr(store_mod, "now_iso", lambda: ts)
        store.record_ports(MAC, [PortState(MAC, p) for p in ports])
        return sorted(p.port for p in store.open_ports()[MAC])

    assert check("2026-01-01T00:00", [80, 9100]) == [80, 9100]
    assert check("2026-01-01T00:05", [80]) == [80, 9100]   # one miss: still open
    assert check("2026-01-01T00:10", [80]) == [80]         # two misses: closed


def test_device_goes_offline_only_after_two_missed_scans(store):
    store.upsert_host(Host(mac=MAC, ip=IP, last_seen="2026-01-01T00:04"))
    before = {h.mac: h for h in store.all_hosts()}
    # Seen during the previous scan (started 00:03): one miss is tolerated.
    Monitor._record_presence(store, before, [], prev_scan="2026-01-01T00:03")
    assert store.get_host(MAC).online and store.events() == []
    # Not seen since before the previous scan started: offline.
    Monitor._record_presence(store, before, [], prev_scan="2026-01-01T00:05")
    assert not store.get_host(MAC).online
    assert [e.kind for e in store.events()] == ["offline"]


def test_v02_acked_alerts_become_resolved(tmp_path):
    import sqlite3
    db = tmp_path / "v02.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            severity INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}', acked INTEGER NOT NULL DEFAULT 0);
        INSERT INTO alerts (ts, severity, kind, message, acked) VALUES ('2026-01-01', 30, 'new_host', 'a', 1);
        INSERT INTO alerts (ts, severity, kind, message, acked) VALUES ('2026-01-01', 30, 'new_host', 'b', 0);
    """)
    conn.commit()
    conn.close()
    with Store(db) as s:
        assert s.status_counts()["resolved"] == 1 and s.status_counts()["new"] == 1


# --- Risk & playbooks ---------------------------------------------------------
def test_risk_score_is_explained():
    h = Host(mac=MAC, ip=IP, trusted=False, vendor="randomized MAC")
    ports = [PortState(MAC, 3389), PortState(MAC, 22), PortState(MAC, 80)]
    factors = risk_factors(h, ports, ["CRITICAL", "HIGH"])
    assert [f["points"] for f in factors] == [30, 50, 14, 5]
    assert risk_score(h, ports, ["CRITICAL", "HIGH"]) == 99
    assert risk_score(Host(mac=MAC, trusted=True), [], []) == 0


def test_every_detector_kind_has_a_playbook():
    kinds = {"gateway_mac_changed", "gateway_arp_spoof", "arp_spoof", "arp_mismatch",
             "duplicate_mac", "rogue_dhcp", "port_scan", "new_port", "new_host",
             "ip_changed_hands", "dhcp_server_learned"}
    assert kinds <= set(PLAYBOOKS)
    pb = playbook("gateway_arp_spoof")
    assert pb["mitre"][0]["id"] == "T1557.002"
    assert pb["mitre"][0]["url"] == "https://attack.mitre.org/techniques/T1557/002/"
    assert playbook("something_new")["title"] == "Something new"


# --- API ----------------------------------------------------------------------
@pytest.fixture
def server(tmp_path):
    db = tmp_path / "soc.db"
    with Store(db) as s:
        s.upsert_host(Host(mac=MAC, ip=IP, hostname="=cmd|' /C calc'!A0", trusted=False))
        s.record_ports(MAC, [PortState(MAC, 3389, service="rdp")])
        for sev in (Severity.CRITICAL, Severity.MEDIUM):
            s.add_alert(alert(sev=sev, msg=f"{sev.name} thing"))
    srv = DashboardServer(("127.0.0.1", 0), db, None, "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def post_json(srv, path, body):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
    data = json.dumps(body)
    conn.request("POST", path, body=data, headers={"Host": "localhost", "X-NetGuard": "1",
                                                   "Content-Type": "application/json"})
    resp = conn.getresponse()
    out = json.loads(resp.read() or b"{}")
    conn.close()
    return resp.status, out


def test_api_triage_flow(server):
    [med, crit] = request(server, "GET", "/api/alerts")[1]  # newest first
    assert crit["severity"] == "CRITICAL" and crit["mac"] == MAC
    assert post_json(server, f"/api/alerts/{crit['id']}/status",
                     {"status": "investigating", "note": "Checking"})[0] == 200
    assert post_json(server, f"/api/alerts/{crit['id']}/note", {"note": "Found it"})[0] == 200
    detail = request(server, "GET", f"/api/alerts/{crit['id']}")[1]
    assert detail["status"] == "investigating" and "Found it" in detail["notes"]
    assert detail["playbook"]["mitre"][0]["id"] == "T1021"
    assert detail["host"]["mac"] == MAC and len(detail["related"]) == 1

    assert post_json(server, "/api/alerts/bulk", {"ids": [crit["id"], med["id"]], "status": "resolved"}) == \
        (200, {"ok": True, "updated": 2})
    assert request(server, "GET", "/api/alerts")[1] == []  # default view = open
    assert len(request(server, "GET", "/api/alerts?status=resolved")[1]) == 2
    assert post_json(server, "/api/alerts/bulk", {"ids": "1", "status": "resolved"})[0] == 400
    assert post_json(server, f"/api/alerts/{crit['id']}/status", {"status": "bogus"})[0] == 400


def test_api_rejects_non_json_bodies(server):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    conn.request("POST", "/api/alerts/1/note", body="note=hi",
                 headers={"Host": "localhost", "X-NetGuard": "1",
                          "Content-Type": "application/x-www-form-urlencoded"})
    assert conn.getresponse().status == 415


def test_api_suppress_from_alert(server):
    [_, crit] = request(server, "GET", "/api/alerts")[1]
    code, body = post_json(server, "/api/suppressions",
                           {"kind": "new_port", "mac": MAC, "reason": "lab box", "alert_id": crit["id"]})
    assert code == 200
    assert request(server, "GET", f"/api/alerts/{crit['id']}")[1]["status"] == "false_positive"
    [rule] = request(server, "GET", "/api/suppressions")[1]
    assert rule["mac"] == MAC and rule["reason"] == "lab box"
    assert request(server, "DELETE", f"/api/suppressions/{rule['id']}", POST)[0] == 200
    assert post_json(server, "/api/suppressions", {"kind": "<script>"})[0] == 400


def test_api_device_detail_and_edit(server):
    assert post_json(server, f"/api/hosts/{MAC}", {"alias": "Lab box", "notes": "Owner: Sam"})[0] == 200
    h = request(server, "GET", f"/api/hosts/{MAC}")[1]
    assert h["alias"] == "Lab box" and h["notes"] == "Owner: Sam"
    assert h["risk"] > 0 and any("3389" in f["reason"] for f in h["risk_factors"])
    assert len(h["alerts"]) == 2
    assert post_json(server, f"/api/hosts/{MAC}", {"alias": 5})[0] == 400
    # Browsers may URL-encode the colons; both spellings must resolve.
    assert request(server, "GET", f"/api/hosts/{MAC.replace(':', '%3A')}")[0] == 200


def test_api_overview(server):
    ov = request(server, "GET", "/api/overview?days=7")[1]
    assert len(ov["series"]) == 7 and ov["series"][-1]["CRITICAL"] == 1
    assert ov["top_kinds"][0]["kind"] == "new_port"
    assert ov["top_devices"][0]["mac"] == MAC
    assert [a["severity"] for a in ov["urgent"]] == ["CRITICAL"]


def test_csv_export_defuses_formula_injection(server):
    code, body, resp = request(server, "GET", "/api/export/hosts.csv")
    assert code == 200 and "attachment" in resp.getheader("Content-Disposition")
    rows = list(csv.reader(io.StringIO(body.lstrip("﻿"))))
    assert rows[0][0] == "ip" and rows[1][3].startswith("'=")  # hostname neutralized
    code, body, _ = request(server, "GET", "/api/export/alerts.csv?status=all")
    rows = list(csv.reader(io.StringIO(body.lstrip("﻿"))))
    assert len(rows) == 3 and rows[1][7] == "T1021;T1133"
    code, data, _ = request(server, "GET", "/api/export/alerts.json?status=all")
    assert code == 200 and data[0]["mitre"] == ["T1021", "T1133"]


def test_monitor_status_includes_config_interval():
    m = Monitor(":memory:", Config())
    assert m.status.interval == 300 and not m.status.scanning
