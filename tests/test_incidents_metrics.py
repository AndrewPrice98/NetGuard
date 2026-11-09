"""Incident correlation, audit trail, SOC metrics and SIEM formats."""

import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from netguard import siem
from netguard.config import Config
from netguard.correlate import compression, correlate
from netguard.demo import build_demo_db
from netguard.incidents import incident_markdown, load_incidents, set_incident_status
from netguard.metrics import coverage, response_times, rule_fidelity, soc_metrics
from netguard.models import Alert, Host, Severity
from netguard.notify import JsonlSink, SyslogSink, build_sinks
from netguard.store import Store
from netguard.web.server import DashboardServer
from tests.test_soc import post_json
from tests.test_web import request

EVIL, EVIL_IP = "de:ad:be:ef:13:37", "10.0.0.87"
GW, GW_IP = "f0:9f:c2:10:20:01", "10.0.0.1"
T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def at(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).isoformat()


def mk(i, minutes, sev, kind, **details):
    return Alert(sev, kind, f"{kind} #{i}", at(minutes), details, id=i)


HOSTS = [Host(mac=EVIL, ip=EVIL_IP, hostname="kali", last_seen=at(0)),
         Host(mac=GW, ip=GW_IP, trusted=True, last_seen=at(0))]

CHAIN = [
    mk(1, 0, Severity.MEDIUM, "new_host", mac=EVIL, ip=EVIL_IP),
    mk(2, 20, Severity.HIGH, "port_scan", src=EVIL_IP),  # IP only: resolved to the MAC
    mk(3, 60, Severity.HIGH, "new_port", mac=EVIL, ip=EVIL_IP, port=4444),
    mk(4, 90, Severity.CRITICAL, "gateway_arp_spoof", ip=GW_IP, claimed_mac=EVIL, expected_mac=GW),
]


# --- Correlation --------------------------------------------------------------
def test_kill_chain_becomes_one_incident():
    [inc] = correlate(CHAIN, HOSTS)
    assert inc.id == "INC-0001" and inc.pattern.key == "aitm_chain"
    assert [a.id for a in inc.alerts] == [1, 2, 3, 4]
    assert inc.tactics == ["Initial Access", "Discovery", "Persistence", "Credential Access"]
    assert inc.severity == Severity.CRITICAL and inc.name == "kali" and inc.trusted is False
    iocs = inc.indicators()
    assert iocs["macs"] == [EVIL] and iocs["ips"] == [EVIL_IP] and iocs["ports"] == ["tcp/4444"]
    assert iocs["impersonated"] == [GW_IP]  # the gateway is the victim, not an IOC
    assert "4 ATT&CK tactics" in inc.narrative()


def test_multi_stage_escalation_and_promotion_rules():
    no_spoof = CHAIN[:3]
    [inc] = correlate(no_spoof, HOSTS)
    assert inc.pattern.key == "recon_to_exposure"
    assert inc.escalated and inc.severity == Severity.CRITICAL  # HIGH + 3 tactics
    # A lone MEDIUM stays an alert; a lone LOW never becomes a case.
    assert correlate([mk(9, 0, Severity.MEDIUM, "new_host", mac=EVIL)], HOSTS) == []
    assert correlate([mk(9, 0, Severity.LOW, "ip_changed_hands", ip=EVIL_IP)], HOSTS) == []
    # Two MEDIUMs on one device do.
    two = [mk(9, 0, Severity.MEDIUM, "new_host", mac=EVIL), mk(10, 5, Severity.MEDIUM, "new_port", mac=EVIL, port=8080)]
    assert len(correlate(two, HOSTS)) == 1


def test_window_splits_and_suppressed_alerts_are_ignored():
    late = mk(5, 60 * 30, Severity.HIGH, "new_port", mac=EVIL, port=22)  # 30 h later
    incidents = correlate(CHAIN + [late], HOSTS)
    assert sorted(len(i.alerts) for i in incidents) == [1, 4]
    quiet = mk(6, 95, Severity.CRITICAL, "rogue_dhcp", server_mac=EVIL)
    quiet.status = "suppressed"
    assert sum(len(i.alerts) for i in correlate(CHAIN + [quiet], HOSTS)) == 4


def test_incident_status_is_derived_from_alerts():
    alerts = [mk(a.id, 0, a.severity, a.kind, **a.details) for a in CHAIN]
    [inc] = correlate(alerts, HOSTS)
    assert inc.status == "new"
    alerts[0].status = "investigating"
    assert correlate(alerts, HOSTS)[0].status == "investigating"
    for a in alerts:
        a.status = "false_positive"
    assert correlate(alerts, HOSTS)[0].status == "false_positive"
    alerts[0].status = "resolved"
    assert correlate(alerts, HOSTS)[0].status == "resolved"
    assert compression(alerts, correlate(alerts, HOSTS))["ratio"] == 4.0


# --- Audit trail & metrics ----------------------------------------------------
@pytest.fixture
def store():
    s = Store(":memory:")
    for h in HOSTS:
        s.upsert_host(h)
    yield s
    s.close()


def test_audit_trail_and_response_times(store):
    a = Alert(Severity.HIGH, "port_scan", "scan", at(0), {"src": EVIL_IP})
    store.add_alert(a)
    store.set_alert_status(a.id, "investigating", "looking", ts=at(12))
    store.set_alert_status(a.id, "investigating", ts=at(13))  # no-op: not logged
    store.set_alert_status(a.id, "resolved", ts=at(50))
    hist = store.alert_history(a.id)
    assert [(h["from_status"], h["to_status"]) for h in hist] == \
        [("", "new"), ("new", "investigating"), ("investigating", "resolved")]
    assert hist[1]["note"] == "looking"
    assert response_times(store.get_alert(a.id), hist) == (12 * 60, 50 * 60)
    # Closed straight from "new": triage and close happen together.
    b = Alert(Severity.LOW, "ip_changed_hands", "x", at(0))
    store.add_alert(b)
    store.set_alert_status(b.id, "false_positive", ts=at(5))
    assert response_times(b, store.alert_history(b.id)) == (300, 300)


def test_soc_metrics_and_rule_fidelity(tmp_path):
    with Store(build_demo_db(tmp_path / "demo.db")) as s:
        m = soc_metrics(s, 30)
        assert m["mtta"]["n"] > 5 and 0 < m["mtta"]["median"] < m["mttr"]["median"]
        assert 0 < m["false_positive_rate"] < 1 and m["open"] > 0
        rules = {r["kind"]: r for r in rule_fidelity(s, 30)}
        assert rules["port_scan"]["false_positive"] == 1 and rules["port_scan"]["tp_rate"] == 0.0
        assert rules["port_scan"]["suppression_rules"] == 1
        assert rules["rogue_dhcp"]["alerts"] == 0  # every rule listed, even silent ones
        assert rules["gateway_arp_spoof"]["validated_by"] == "arp_spoof_gateway"
        incidents = load_incidents(s)
        top = incidents[0]
        assert top.pattern.key == "aitm_chain" and len(top.alerts) == 4 and top.is_open
        assert top.id == "INC-0015"  # referenced by docs/case-study-INC-0015.md and the README
        md = incident_markdown(s, top)
        assert "## Timeline" in md and "T1557.002" in md and "de:ad:be:ef:13:37" in md


def test_incident_actions_preserve_closed_alerts(store):
    for a in CHAIN:
        a.id = None
        store.add_alert(a)
    store.set_alert_status(CHAIN[0].id, "false_positive")
    [inc] = load_incidents(store, 3650)
    assert set_incident_status(store, inc, "resolved", "Contained") == 3
    assert store.get_alert(CHAIN[0].id).status == "false_positive"  # not overwritten
    assert "[INC-" in store.get_alert(CHAIN[1].id).notes


def test_coverage_lists_techniques_by_tactic():
    cols = {c["tactic"]: {t["id"] for t in c["techniques"]} for c in coverage()}
    assert "T1557.002" in cols["Credential Access"] and "T1046" in cols["Discovery"]
    assert list(cols)[0] == "Initial Access"  # matrix order


def test_markdown_report_neutralizes_hostile_names(store):
    store.upsert_host(Host(mac=EVIL, ip=EVIL_IP, hostname="<img src=x>|`rm`"))
    for a in CHAIN:
        a.id = None
        store.add_alert(a)
    md = incident_markdown(store, load_incidents(store, 3650)[0])
    import re
    assert not re.search(r"(?<!\\)<img", md) and "\\<img" in md  # only escaped forms remain


# --- SIEM formats ---------------------------------------------------------------
def test_ecs_mapping():
    a = mk(7, 0, Severity.CRITICAL, "gateway_arp_spoof", ip=GW_IP, claimed_mac=EVIL)
    doc = siem.to_ecs(a)
    assert doc["event"]["kind"] == "alert" and doc["event"]["severity"] == 99
    assert doc["source"] == {"ip": GW_IP, "mac": "DE-AD-BE-EF-13-37"}
    assert doc["threat"]["technique"][0]["id"] == "T1557"
    assert doc["threat"]["technique"][0]["subtechnique"][0]["id"] == "T1557.002"
    assert doc["rule"]["id"] == "gateway_arp_spoof" and "@timestamp" in doc
    port = siem.to_ecs(mk(8, 0, Severity.HIGH, "new_port", mac=EVIL, ip=EVIL_IP, port=4444))
    assert port["destination"]["port"] == 4444


def test_cef_escaping():
    a = Alert(Severity.HIGH, "new_port", "evil|name=x\\y\nnext", at(0),
              {"mac": EVIL, "ip": EVIL_IP, "port": 3389}, id=3)
    line = siem.to_cef(a)
    # 7 header fields; pipes need no escaping in the extension (CEF spec).
    *header, ext = line.split("|", 7)
    assert header[:3] == ["CEF:0", "NetGuard", "NetGuard"]
    assert header[4:] == ["new_port", "New listening service", "8"]
    assert "msg=evil|name\\=x\\\\y\\nnext" in ext and "\n" not in line
    assert "cs1=T1021,T1133" in ext and "dpt=3389" in ext and "src=10.0.0.87" in ext


def test_log_sinks_and_config(tmp_path):
    log = tmp_path / "a.log"
    sink = JsonlSink(log, "ecs")
    sink.send(CHAIN[3])
    assert json.loads(log.read_text())["event"]["action"] == "gateway_arp_spoof"
    sys_sink = SyslogSink("127.0.0.1", 5514, "cef")
    msg = sys_sink.build(CHAIN[3]).decode()
    assert msg.startswith("<162>1 ") and "CEF:0|NetGuard" in msg  # local4.crit
    assert [type(s).__name__ for s in build_sinks([{"type": "syslog", "host": "10.0.0.5"}])] == ["SyslogSink"]
    with pytest.raises(ValueError):
        Config.from_dict({"alerts": {"log_format": "xml"}})
    assert Config.from_dict({"alerts": {"log_format": "cef"}}).alerts.log_format == "cef"


# --- API ------------------------------------------------------------------------
@pytest.fixture
def demo_server(tmp_path):
    srv = DashboardServer(("127.0.0.1", 0), build_demo_db(tmp_path / "d.db"), None, "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_incident_api(demo_server):
    code, rows, _ = request(demo_server, "GET", "/api/incidents")
    assert code == 200 and rows[0]["pattern"] == "aitm_chain" and all(r["open"] for r in rows)
    inc_id = rows[0]["id"]
    detail = request(demo_server, "GET", f"/api/incidents/{inc_id}")[1]
    assert len(detail["chain"]) == 4 and detail["indicators"]["ports"] == ["tcp/4444"]
    code, md, resp = request(demo_server, "GET", f"/api/incidents/{inc_id}/report.md")
    assert code == 200 and md.startswith(f"# {inc_id}") and "markdown" in resp.getheader("Content-Type")
    assert post_json(demo_server, f"/api/incidents/{inc_id}/status", {"status": "resolved", "note": "Isolated"})[0] == 200
    assert request(demo_server, "GET", f"/api/incidents/{inc_id}")[1]["status"] == "resolved"
    assert post_json(demo_server, f"/api/incidents/{inc_id}/status", {"status": "suppressed"})[0] == 400
    assert request(demo_server, "GET", "/api/incidents/INC-9999")[0] == 404
    alert = request(demo_server, "GET", f"/api/alerts/{detail['alert_ids'][1]}")[1]
    assert alert["incident"]["id"] == inc_id and alert["history"][0]["to_status"] == "new"


def test_metrics_detections_validation_api(demo_server):
    m = request(demo_server, "GET", "/api/metrics")[1]
    assert m["mtta"]["median"] and m["correlation"]["incidents"] >= 3
    d = request(demo_server, "GET", "/api/detections")[1]
    assert len(d["rules"]) >= 11 and d["coverage"] and len(d["scenarios"]) >= 7
    v = request(demo_server, "GET", "/api/validation")[1]
    assert v and all(r["passed"] for r in v)
    status = request(demo_server, "GET", "/api/status")[1]
    assert status["incidents"]["open"] >= 2 and status["incidents"]["critical"] == 1
    code, body, _ = request(demo_server, "GET", "/api/export/alerts.ecs.ndjson?status=all")
    lines = [json.loads(x) for x in body.strip().splitlines()]
    assert code == 200 and all(x["ecs"]["version"] for x in lines)
