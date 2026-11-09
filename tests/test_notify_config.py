import json
import sqlite3

import pytest

from netguard.config import Config
from netguard.models import Alert, Severity
from netguard.notify import (EmailSink, JsonlSink, Notifier, Sink,
                             build_sinks, build_webhook_request)
from netguard.store import Store

ALERT = Alert(Severity.CRITICAL, "gateway_mac_changed", "Gateway 10.0.0.1 MAC changed",
              "2026-11-09T10:00:00+00:00", {"ip": "10.0.0.1"})


class Recorder(Sink):
    def __init__(self, min_severity="INFO"):
        super().__init__(min_severity)
        self.got = []

    def send(self, alert):
        self.got.append(alert)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


# --- Notifier -----------------------------------------------------------------
def test_notifier_dedupes_and_respects_thresholds(store):
    every, urgent = Recorder("INFO"), Recorder("HIGH")
    n = Notifier(store, [every, urgent], suppress_minutes=60, quiet=True)
    low = Alert(Severity.LOW, "ip_changed_hands", "moved")
    assert n.emit(ALERT) and n.emit(low)
    assert not n.emit(Alert(Severity.CRITICAL, ALERT.kind, ALERT.message))  # duplicate
    assert [a.kind for a in every.got] == ["gateway_mac_changed", "ip_changed_hands"]
    assert [a.kind for a in urgent.got] == ["gateway_mac_changed"]
    assert len(store.recent_alerts()) == 2


def test_broken_sink_does_not_break_emit(store):
    class Boom(Sink):
        def send(self, alert):
            raise RuntimeError("nope")
    assert Notifier(store, [Boom("INFO")], quiet=True).emit(ALERT)


def test_jsonl_sink(tmp_path):
    path = tmp_path / "alerts.jsonl"
    JsonlSink(path).send(ALERT)
    record = json.loads(path.read_text())
    assert record["severity"] == "CRITICAL" and record["kind"] == "gateway_mac_changed"


# --- Webhook payloads ---------------------------------------------------------
def test_discord_payload():
    req = build_webhook_request("discord", "https://discord.example/hook", ALERT)
    body = json.loads(req.data)
    assert body["username"] == "NetGuard" and "MAC changed" in body["content"]
    assert req.get_method() == "POST"


def test_slack_payload():
    body = json.loads(build_webhook_request("slack", "https://h", ALERT).data)
    assert body["text"].startswith("*NetGuard CRITICAL")


def test_ntfy_headers_and_no_header_injection():
    evil = Alert(Severity.HIGH, "new_host", "New device: evil\r\nX-Injected: 1")
    req = build_webhook_request("ntfy", "https://ntfy.sh/topic", evil)
    assert req.get_header("Priority") == "4"
    assert b"\n" not in req.data and "\n" not in req.get_header("Title")


def test_unknown_webhook_format():
    with pytest.raises(ValueError):
        build_webhook_request("carrier-pigeon", "https://h", ALERT)


def test_email_message():
    sink = EmailSink(host="smtp.example.com", to=["me@example.com"],
                     username="bot@example.com", **{"from": "netguard@example.com"})
    msg = sink.build(ALERT)
    assert msg["To"] == "me@example.com" and msg["From"] == "netguard@example.com"
    assert msg["Subject"].startswith("[NetGuard] CRITICAL")
    assert '"ip": "10.0.0.1"' in msg.get_content()


def test_build_sinks():
    sinks = build_sinks([
        {"type": "desktop", "min_severity": "MEDIUM"},
        {"type": "webhook", "format": "ntfy", "url": "https://ntfy.sh/x"},
        {"type": "email", "host": "smtp.example.com", "to": "a@b.c"},
    ], jsonl="x.jsonl")
    assert [type(s).__name__ for s in sinks] == ["JsonlSink", "DesktopSink", "WebhookSink", "EmailSink"]
    assert sinks[1].min_severity == Severity.MEDIUM


# --- Config -------------------------------------------------------------------
def test_config_defaults_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config.load()
    assert cfg.scan.interval == 300 and cfg.web.host == "127.0.0.1" and cfg.notify == []


def test_config_from_toml(tmp_path):
    path = tmp_path / "netguard.toml"
    path.write_text("""
[scan]
subnet = "192.168.1.0/24"
interval = 60
[sniff]
enabled = true
dhcp_servers = ["192.168.1.1"]
[[notify]]
type = "webhook"
format = "discord"
url = "https://discord.example/hook"
min_severity = "medium"
""", encoding="utf-8")
    cfg = Config.load(path)
    assert cfg.scan.subnet == "192.168.1.0/24" and cfg.scan.interval == 60
    assert cfg.sniff.enabled and cfg.sniff.dhcp_servers == ["192.168.1.1"]
    assert cfg.notify[0]["format"] == "discord"


def test_config_rejects_typos(tmp_path):
    path = tmp_path / "netguard.toml"
    path.write_text("[scan]\nintreval = 60\n", encoding="utf-8")
    with pytest.raises(ValueError, match="intreval"):
        Config.load(path)


def test_config_missing_explicit_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        Config.load(tmp_path / "nope.toml")


# --- Store migration ----------------------------------------------------------
def test_v01_database_is_migrated(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE hosts (mac TEXT PRIMARY KEY, ip TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT '',
            trusted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            severity INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}');
        INSERT INTO hosts (mac, ip, trusted) VALUES ('aa:bb:cc:dd:ee:ff', '10.0.0.5', 1);
        INSERT INTO alerts (ts, severity, kind, message) VALUES ('2026-01-01', 30, 'new_host', 'x');
    """)
    conn.commit()
    conn.close()

    with Store(db) as s:
        host = s.get_host("aa:bb:cc:dd:ee:ff")
        assert host.trusted and host.device_type == ""
        [alert] = s.recent_alerts()
        assert alert.acked is False and s.ack_alert(alert.id)
        assert s.alert_counts()["MEDIUM"] == 0


def test_hosts_sort_numerically(store):
    from netguard.models import Host
    for ip in ("10.0.0.104", "10.0.0.24", "10.0.0.3"):
        store.upsert_host(Host(mac=ip, ip=ip))
    assert [h.ip for h in store.all_hosts()] == ["10.0.0.3", "10.0.0.24", "10.0.0.104"]
