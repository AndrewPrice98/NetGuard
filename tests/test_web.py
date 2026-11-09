"""End-to-end tests against a real dashboard server on a random port."""

import http.client
import json
import threading

import pytest

from netguard.engine import Status
from netguard.models import Alert, Host, PortState, Severity
from netguard.report import build_report
from netguard.store import Store
from netguard.web.server import DashboardServer

EVIL_NAME = '<img src=x onerror="alert(1)">'


class FakeMonitor:
    def __init__(self):
        self.status = Status(interval=300, subnet="10.0.0.0/24", gateway="10.0.0.1")
        self.triggered = 0

    def trigger_scan(self):
        self.triggered += 1
        return self.triggered == 1  # second press while "scanning" is refused


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "web.db"
    with Store(path) as s:
        s.upsert_host(Host(mac="f8:79:0a:43:0d:31", ip="10.0.0.1", trusted=True, device_type="router"))
        s.upsert_host(Host(mac="de:ad:be:ef:00:01", ip="10.0.0.66", hostname=EVIL_NAME))
        s.record_ports("f8:79:0a:43:0d:31", [PortState("f8:79:0a:43:0d:31", 443, service="https")])
        s.add_alert(Alert(Severity.MEDIUM, "new_host", f"New device: {EVIL_NAME}"))
    return path


def start(db, token=""):
    monitor = FakeMonitor()
    server = DashboardServer(("127.0.0.1", 0), db, monitor, token)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, monitor


@pytest.fixture
def server(db):
    srv, mon = start(db)
    yield srv, mon
    srv.shutdown()
    srv.server_close()


def request(srv, method, path, headers=None, host="localhost"):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
    conn.request(method, path, headers={"Host": host, **(headers or {})})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(body), resp
    except ValueError:
        return resp.status, body.decode(), resp


POST = {"X-NetGuard": "1"}


# --- Reading -------------------------------------------------------------------
def test_status(server):
    srv, _ = server
    code, body, _ = request(srv, "GET", "/api/status")
    assert code == 200
    assert body["hosts"] == 2 and body["untrusted"] == 1 and body["monitoring"]
    assert body["alerts"]["MEDIUM"] == 1 and body["status"]["subnet"] == "10.0.0.0/24"


def test_hosts_include_ports_and_types(server):
    srv, _ = server
    code, hosts, _ = request(srv, "GET", "/api/hosts")
    router = next(h for h in hosts if h["ip"] == "10.0.0.1")
    assert router["type_label"] == "Router"
    [port] = router["ports"]
    assert port["port"] == 443 and port["service"] == "https" and port["open"] and not port["risky"]
    evil = next(h for h in hosts if h["ip"] == "10.0.0.66")
    assert evil["risk"] >= 30 and evil["open_alerts"] == 0  # untrusted; its alert has no MAC detail


def test_alerts_filtering(server):
    srv, _ = server
    assert len(request(srv, "GET", "/api/alerts")[1]) == 1
    assert request(srv, "GET", "/api/alerts?min=HIGH")[1] == []
    assert request(srv, "GET", "/api/alerts?min=BOGUS")[0] == 400


def test_static_and_security_headers(server):
    srv, _ = server
    code, body, resp = request(srv, "GET", "/")
    assert code == 200 and "<title>NetGuard</title>" in body
    assert "script-src 'self'" in resp.getheader("Content-Security-Policy")
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert request(srv, "GET", "/static/app.js")[0] == 200


def test_path_traversal_blocked(server):
    srv, _ = server
    for path in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/x.js"):
        assert request(srv, "GET", path)[0] == 404


# --- Writing -------------------------------------------------------------------
def test_trust_untrust_forget(server, db):
    srv, _ = server
    mac = "de:ad:be:ef:00:01"
    assert request(srv, "POST", f"/api/hosts/{mac}/trust", POST)[0] == 200
    with Store(db) as s:
        assert s.get_host(mac).trusted
    assert request(srv, "POST", f"/api/hosts/{mac}/untrust", POST)[0] == 200
    assert request(srv, "DELETE", f"/api/hosts/{mac}", POST)[0] == 200
    with Store(db) as s:
        assert s.get_host(mac) is None
    assert request(srv, "POST", f"/api/hosts/{mac}/trust", POST)[0] == 404


def test_ack(server):
    srv, _ = server
    [alert] = request(srv, "GET", "/api/alerts")[1]
    assert request(srv, "POST", f"/api/alerts/{alert['id']}/ack", POST)[0] == 200
    assert request(srv, "GET", "/api/alerts?unacked=1")[1] == []
    assert request(srv, "POST", "/api/alerts/999/ack", POST)[0] == 404


def test_scan_trigger_and_conflict(server):
    srv, mon = server
    assert request(srv, "POST", "/api/scan", POST)[0] == 200
    assert request(srv, "POST", "/api/scan", POST)[0] == 409


# --- Security ------------------------------------------------------------------
def test_csrf_header_required_for_writes(server):
    srv, mon = server
    assert request(srv, "POST", "/api/scan")[0] == 403
    assert mon.triggered == 0


def test_dns_rebinding_blocked(server):
    srv, _ = server
    assert request(srv, "GET", "/api/hosts", host="attacker.example:8000")[0] == 403
    assert request(srv, "GET", "/api/hosts", host="127.0.0.1:8000")[0] == 200


def test_token_mode(db):
    srv, _ = start(db, token="s3cret")
    try:
        assert request(srv, "GET", "/api/status")[0] == 401
        assert request(srv, "GET", "/api/status", {"X-NetGuard-Token": "wrong"})[0] == 401
        code, _, _ = request(srv, "GET", "/api/status", {"X-NetGuard-Token": "s3cret"},
                             host="192.168.1.50:8000")
        assert code == 200
        assert request(srv, "GET", "/report")[0] == 401
        assert request(srv, "GET", "/report?token=s3cret")[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()


def test_view_only_mode(db):
    srv = DashboardServer(("127.0.0.1", 0), db, None, "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert request(srv, "POST", "/api/scan", POST)[0] == 503
        assert request(srv, "GET", "/api/status")[1]["monitoring"] is False
    finally:
        srv.shutdown()
        srv.server_close()


# --- Report --------------------------------------------------------------------
def test_report_escapes_hostile_hostnames(server, db):
    srv, _ = server
    code, html, resp = request(srv, "GET", "/report?days=7")
    assert code == 200 and "NetGuard security report" in html
    assert EVIL_NAME not in html and "&lt;img src=x" in html
    assert resp.getheader("Content-Security-Policy").startswith("default-src 'none'")


def test_report_contents(db):
    with Store(db) as s:
        # No baseline marker: both devices count as the baseline, so none are new.
        html = build_report(s, days=7)
        assert "New devices (0)" in html and "Device inventory (2)" in html
        assert "443/https" in html
        # Baseline taken long ago: both devices joined after it.
        s.set_meta("baseline_at", "2000-01-01T00:00:00+00:00")
        assert "New devices (2)" in build_report(s, days=7)
