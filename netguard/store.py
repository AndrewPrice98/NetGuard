"""
SQLite persistence for NetGuard.

One small database holds the baseline (hosts + their ports), metadata (e.g.
the gateway's IP and MAC), the alert queue with its triage state, an event
log for investigations, and suppression rules for tuning out noise.
Everything goes through this class so the rest of the code never writes SQL.

The scanner and the web dashboard run in different threads, so each thread
opens its own Store; WAL mode lets the dashboard read while a scan writes.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import (ALERT_STATUSES, OPEN_STATUSES, Alert, Event, Host,
                     PortState, Severity)

# --- Schema -----------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL DEFAULT '',
    last_seen   TEXT NOT NULL DEFAULT '',
    trusted     INTEGER NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL DEFAULT '',
    alias       TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    online      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ports (
    mac        TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    service    TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT '',
    last_seen  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (mac, port, proto)
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    severity   INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    message    TEXT NOT NULL,
    details    TEXT NOT NULL DEFAULT '{}',
    acked      INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'new',
    notes      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    mac     TEXT NOT NULL DEFAULT '',
    ip      TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_mac ON events (mac);

CREATE TABLE IF NOT EXISTS suppressions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,             -- alert kind, or '*' for any
    mac      TEXT NOT NULL DEFAULT '',  -- blank = any device
    ip       TEXT NOT NULL DEFAULT '',
    reason   TEXT NOT NULL DEFAULT '',
    created  TEXT NOT NULL,
    hits     INTEGER NOT NULL DEFAULT 0,
    last_hit TEXT NOT NULL DEFAULT ''
);

-- Audit trail: every triage transition, so response times (MTTA/MTTR)
-- can be measured and every closed alert shows who-did-what-when.
CREATE TABLE IF NOT EXISTS alert_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    from_status TEXT NOT NULL DEFAULT '',
    to_status   TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alert_history_alert ON alert_history (alert_id);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Columns added after v0.1; added to older databases on open.
MIGRATIONS = {
    "hosts": {
        "device_type": "TEXT NOT NULL DEFAULT ''",
        "alias": "TEXT NOT NULL DEFAULT ''",
        "notes": "TEXT NOT NULL DEFAULT ''",
        "online": "INTEGER NOT NULL DEFAULT 1",
    },
    "alerts": {
        "acked": "INTEGER NOT NULL DEFAULT 0",
        "status": "TEXT NOT NULL DEFAULT 'new'",
        "notes": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    },
}


def now_iso() -> str:
    """UTC timestamp, second precision — sortable as plain text."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_ago(**delta: float) -> str:
    """now_iso() shifted into the past, e.g. iso_ago(days=7)."""
    ts = datetime.now(timezone.utc) - timedelta(**delta)
    return ts.replace(microsecond=0).isoformat()


def ip_sort_key(ip: str) -> tuple[int, int]:
    """Sort 10.0.0.24 before 10.0.0.104; empty/invalid IPs last."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


# --- Store ------------------------------------------------------------------
class Store:
    """Thin wrapper around a SQLite connection (one per thread)."""

    def __init__(self, path: Path | str = "netguard.db") -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        for table, columns in MIGRATIONS.items():
            have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in columns.items():
                if col not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        # v0.2 "acked" alerts become "resolved" in the triage workflow.
        self.conn.execute("UPDATE alerts SET status = 'resolved' "
                          "WHERE acked = 1 AND status = 'new'")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- hosts ---------------------------------------------------------------
    def get_host(self, mac: str) -> Host | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE mac = ?", (mac,)).fetchone()
        return _row_to_host(row) if row else None

    def get_host_by_ip(self, ip: str) -> Host | None:
        """Most recently seen host that last held this IP."""
        row = self.conn.execute(
            "SELECT * FROM hosts WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return _row_to_host(row) if row else None

    def all_hosts(self) -> list[Host]:
        rows = self.conn.execute("SELECT * FROM hosts").fetchall()
        return sorted((_row_to_host(r) for r in rows), key=lambda h: ip_sort_key(h.ip))

    def upsert_host(self, host: Host) -> None:
        """Insert or refresh a host seen on the network (marks it online).

        Never downgrades `trusted` or `first_seen`, never blanks a hostname,
        vendor or type learned earlier, and never touches analyst fields
        (alias, notes) of an existing host.
        """
        ts = host.last_seen or now_iso()
        self.conn.execute(
            """
            INSERT INTO hosts (mac, ip, hostname, vendor, first_seen, last_seen,
                               trusted, device_type, alias, notes, online)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(mac) DO UPDATE SET
                ip          = excluded.ip,
                hostname    = CASE WHEN excluded.hostname != '' THEN excluded.hostname
                                   ELSE hosts.hostname END,
                vendor      = CASE WHEN excluded.vendor != '' THEN excluded.vendor
                                   ELSE hosts.vendor END,
                device_type = CASE WHEN excluded.device_type != '' THEN excluded.device_type
                                   ELSE hosts.device_type END,
                last_seen   = excluded.last_seen,
                trusted     = MAX(hosts.trusted, excluded.trusted),
                online      = 1
            """,
            (host.mac, host.ip, host.hostname, host.vendor, host.first_seen or ts, ts,
             int(host.trusted), host.device_type, host.alias, host.notes),
        )
        self.conn.commit()

    def set_device_type(self, mac: str, device_type: str) -> None:
        self.conn.execute("UPDATE hosts SET device_type = ? WHERE mac = ?",
                          (device_type, mac))
        self.conn.commit()

    def set_online(self, mac: str, online: bool) -> None:
        self.conn.execute("UPDATE hosts SET online = ? WHERE mac = ?", (int(online), mac))
        self.conn.commit()

    def update_host_info(self, mac: str, alias: str | None = None,
                         notes: str | None = None) -> bool:
        """Analyst-editable fields."""
        sets, params = [], []
        if alias is not None:
            sets.append("alias = ?")
            params.append(alias.strip()[:80])
        if notes is not None:
            sets.append("notes = ?")
            params.append(notes.strip()[:4000])
        if not sets:
            return self.get_host(mac) is not None
        cur = self.conn.execute(f"UPDATE hosts SET {', '.join(sets)} WHERE mac = ?",
                                (*params, mac))
        self.conn.commit()
        return cur.rowcount > 0

    def set_trusted(self, mac: str, trusted: bool = True) -> bool:
        cur = self.conn.execute(
            "UPDATE hosts SET trusted = ? WHERE mac = ?", (int(trusted), mac)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def forget_host(self, mac: str) -> bool:
        """Remove a host and its ports; it will be 'new' if seen again."""
        cur = self.conn.execute("DELETE FROM hosts WHERE mac = ?", (mac,))
        self.conn.execute("DELETE FROM ports WHERE mac = ?", (mac,))
        self.conn.execute("DELETE FROM meta WHERE key IN (?, ?)",
                          (f"ports_scanned:{mac}", f"ports_scanned_prev:{mac}"))
        self.conn.commit()
        return cur.rowcount > 0

    # -- ports ---------------------------------------------------------------
    def get_ports(self, mac: str) -> list[PortState]:
        rows = self.conn.execute(
            "SELECT * FROM ports WHERE mac = ? ORDER BY port", (mac,)
        ).fetchall()
        return [PortState(**dict(r)) for r in rows]

    def all_ports(self) -> dict[str, list[PortState]]:
        """{mac: [ports ever seen]} in one query, for listings."""
        out: dict[str, list[PortState]] = {}
        for r in self.conn.execute("SELECT * FROM ports ORDER BY port"):
            out.setdefault(r["mac"], []).append(PortState(**dict(r)))
        return out

    def open_ports(self) -> dict[str, list[PortState]]:
        """{mac: [ports currently considered open]}.

        The ports table remembers every port ever seen (that's the baseline).
        A port counts as *open* if it answered in either of the host's last
        two checks: sleepy devices (printers, IoT) often miss one probe, and
        a single miss shouldn't flap the port closed and open again.
        """
        def checks(prefix: str) -> dict[str, str]:
            return {r["key"].split(":", 1)[1]: r["value"] for r in self.conn.execute(
                "SELECT key, value FROM meta WHERE key LIKE ?", (f"{prefix}:%",))}
        latest, previous = checks("ports_scanned"), checks("ports_scanned_prev")
        return {mac: [p for p in ports
                      if p.last_seen >= previous.get(mac, latest.get(mac, ""))]
                for mac, ports in self.all_ports().items()}

    def has_port_baseline(self, mac: str) -> bool:
        """True once this host's ports have been recorded at least once."""
        return self.get_meta(f"ports_scanned:{mac}") is not None

    def record_ports(self, mac: str, ports: list[PortState]) -> None:
        ts = now_iso()
        for p in ports:
            self.conn.execute(
                """
                INSERT INTO ports (mac, port, proto, service, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac, port, proto) DO UPDATE SET
                    service   = excluded.service,
                    last_seen = excluded.last_seen
                """,
                (mac, p.port, p.proto, p.service, p.first_seen or ts, ts),
            )
        if (prev := self.get_meta(f"ports_scanned:{mac}")) is not None:
            self.set_meta(f"ports_scanned_prev:{mac}", prev)
        self.set_meta(f"ports_scanned:{mac}", ts)  # commits

    # -- alerts --------------------------------------------------------------
    def add_alert(self, alert: Alert) -> None:
        if not alert.ts:
            alert.ts = now_iso()
        cur = self.conn.execute(
            "INSERT INTO alerts (ts, severity, kind, message, details, status, acked, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.ts, int(alert.severity), alert.kind, alert.message,
             json.dumps(alert.details, sort_keys=True), alert.status,
             int(alert.acked), alert.ts),
        )
        alert.id = cur.lastrowid
        alert.updated_at = alert.ts
        self._log_transition(alert.id, alert.ts, "", alert.status)
        self.conn.commit()

    def _log_transition(self, alert_id: int, ts: str, old: str, new: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT INTO alert_history (alert_id, ts, from_status, to_status, note)"
            " VALUES (?, ?, ?, ?, ?)", (alert_id, ts, old, new, note[:300]))

    def alert_history(self, alert_id: int) -> list[dict]:
        """Status transitions for one alert, oldest first."""
        return [dict(r) for r in self.conn.execute(
            "SELECT ts, from_status, to_status, note FROM alert_history"
            " WHERE alert_id = ? ORDER BY id", (alert_id,))]

    def all_history(self, since: str | None = None) -> dict[int, list[dict]]:
        """{alert_id: [transitions]} for alerts raised since `since`."""
        sql = ("SELECT h.alert_id, h.ts, h.from_status, h.to_status FROM alert_history h"
               " JOIN alerts a ON a.id = h.alert_id")
        params: list = []
        if since:
            sql += " WHERE a.ts >= ?"
            params.append(since)
        out: dict[int, list[dict]] = {}
        for r in self.conn.execute(sql + " ORDER BY h.id", params):
            out.setdefault(r["alert_id"], []).append(dict(r))
        return out

    def get_alert(self, alert_id: int) -> Alert | None:
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _row_to_alert(row) if row else None

    def recent_alerts(self, limit: int = 50, min_severity: Severity = Severity.INFO,
                      unacked_only: bool = False, since: str | None = None,
                      statuses: list[str] | None = None, kind: str | None = None,
                      query: str | None = None, mac: str | None = None) -> list[Alert]:
        """Newest first, with the filters an analyst's queue needs."""
        sql = "SELECT * FROM alerts WHERE severity >= ?"
        params: list = [int(min_severity)]
        if unacked_only:
            statuses = list(OPEN_STATUSES)
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            params += statuses
        if since:
            sql += " AND ts >= ?"
            params.append(since)
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if query:
            sql += " AND (message LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\' OR notes LIKE ? ESCAPE '\\')"
            like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params += [like, like, like]
        if mac:
            sql += " AND details LIKE ?"
            params.append(f'%"{mac}"%')
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [_row_to_alert(r) for r in self.conn.execute(sql, params)]

    def alert_counts(self, unacked_only: bool = True,
                     since: str | None = None) -> dict[str, int]:
        """{severity name: count}, every severity present (zeros included)."""
        sql = "SELECT severity, COUNT(*) AS n FROM alerts WHERE 1=1"
        params: list = []
        if unacked_only:
            sql += f" AND status IN ({','.join('?' * len(OPEN_STATUSES))})"
            params += OPEN_STATUSES
        if since:
            sql += " AND ts >= ?"
            params.append(since)
        sql += " GROUP BY severity"
        counts = {s.name: 0 for s in Severity}
        for r in self.conn.execute(sql, params):
            counts[Severity(r["severity"]).name] = r["n"]
        return counts

    def status_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in ALERT_STATUSES}
        for r in self.conn.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"):
            counts[r["status"]] = r["n"]
        return counts

    def set_alert_status(self, alert_id: int, status: str, note: str = "",
                         ts: str | None = None) -> bool:
        """Move an alert through the triage workflow, optionally with a note.

        Every real transition is written to the audit trail. `ts` exists for
        imports and the demo; normal callers let it default to now.
        """
        if status not in ALERT_STATUSES:
            raise ValueError(f"Unknown status {status!r}")
        ts = ts or now_iso()
        row = self.conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            return False
        self.conn.execute(
            "UPDATE alerts SET status = ?, acked = ?, updated_at = ? WHERE id = ?",
            (status, int(status not in OPEN_STATUSES), ts, alert_id))
        if row["status"] != status:
            self._log_transition(alert_id, ts, row["status"], status, " ".join(note.split()))
        self.conn.commit()
        if note.strip():
            self.add_alert_note(alert_id, note, ts=ts)
        return True

    def set_status_bulk(self, ids: list[int], status: str, note: str = "") -> int:
        return sum(self.set_alert_status(i, status, note) for i in ids)

    def add_alert_note(self, alert_id: int, note: str, ts: str | None = None) -> bool:
        """Append a timestamped line to the alert's investigation notes."""
        ts = ts or now_iso()
        line = f"[{ts}] {' '.join(note.split())[:1000]}"
        cur = self.conn.execute(
            "UPDATE alerts SET notes = CASE WHEN notes = '' THEN ? ELSE notes || char(10) || ? END,"
            " updated_at = ? WHERE id = ?", (line, line, ts, alert_id))
        self.conn.commit()
        return cur.rowcount > 0

    def ack_alert(self, alert_id: int) -> bool:
        return self.set_alert_status(alert_id, "resolved")

    def ack_all(self) -> int:
        ids = [r["id"] for r in self.conn.execute(
            "SELECT id FROM alerts WHERE status IN ('new', 'investigating')")]
        return self.set_status_bulk(ids, "resolved")

    # -- statistics ----------------------------------------------------------
    def alert_series(self, days: int = 14) -> list[dict]:
        """Alerts per UTC day per severity, oldest first, zero-filled."""
        today = datetime.now(timezone.utc).date()
        series = {(today - timedelta(days=i)).isoformat(): {s.name: 0 for s in Severity}
                  for i in range(days - 1, -1, -1)}
        rows = self.conn.execute(
            "SELECT substr(ts, 1, 10) AS day, severity, COUNT(*) AS n FROM alerts "
            "WHERE ts >= ? AND status != 'suppressed' GROUP BY day, severity",
            (min(series),))
        for r in rows:
            if r["day"] in series:
                series[r["day"]][Severity(r["severity"]).name] = r["n"]
        return [{"day": day, **counts} for day, counts in series.items()]

    def top_kinds(self, days: int = 14, limit: int = 6) -> list[dict]:
        rows = self.conn.execute(
            "SELECT kind, COUNT(*) AS n, MAX(severity) AS sev FROM alerts "
            "WHERE ts >= ? AND status != 'suppressed' GROUP BY kind ORDER BY n DESC LIMIT ?",
            (iso_ago(days=days), limit))
        return [{"kind": r["kind"], "count": r["n"], "severity": Severity(r["sev"]).name}
                for r in rows]

    def top_devices(self, days: int = 14, limit: int = 5) -> list[dict]:
        """Devices that generated the most alerts recently."""
        counts: Counter[str] = Counter()
        worst: dict[str, int] = {}
        for a in self.recent_alerts(limit=5000, since=iso_ago(days=days)):
            if a.status == "suppressed":
                continue
            mac, _ = a.entity()
            if mac:
                counts[mac] += 1
                worst[mac] = max(worst.get(mac, 0), int(a.severity))
        return [{"mac": mac, "count": n, "severity": Severity(worst[mac]).name}
                for mac, n in counts.most_common(limit)]

    # -- events --------------------------------------------------------------
    def add_event(self, event: Event) -> None:
        event.ts = event.ts or now_iso()
        cur = self.conn.execute(
            "INSERT INTO events (ts, kind, mac, ip, message, details) VALUES (?, ?, ?, ?, ?, ?)",
            (event.ts, event.kind, event.mac, event.ip, event.message,
             json.dumps(event.details, sort_keys=True)))
        event.id = cur.lastrowid
        self.conn.commit()

    def events(self, limit: int = 200, mac: str | None = None, kind: str | None = None,
               since: str | None = None) -> list[Event]:
        """Newest first."""
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if mac:
            sql += " AND mac = ?"
            params.append(mac)
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if since:
            sql += " AND ts >= ?"
            params.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [Event(kind=r["kind"], message=r["message"], mac=r["mac"], ip=r["ip"],
                      ts=r["ts"], details=json.loads(r["details"]), id=r["id"])
                for r in self.conn.execute(sql, params)]

    def prune(self, keep_days: int = 90) -> None:
        """Retention: drop old events and closed alerts."""
        cutoff = iso_ago(days=keep_days)
        self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        self.conn.execute("DELETE FROM alerts WHERE ts < ? AND status NOT IN ('new', 'investigating')",
                          (cutoff,))
        self.conn.execute("DELETE FROM alert_history WHERE alert_id NOT IN (SELECT id FROM alerts)")
        self.conn.commit()

    # -- suppression rules ---------------------------------------------------
    def add_suppression(self, kind: str, mac: str = "", ip: str = "", reason: str = "") -> int:
        if not kind:
            raise ValueError("A suppression rule needs an alert kind (or '*')")
        cur = self.conn.execute(
            "INSERT INTO suppressions (kind, mac, ip, reason, created) VALUES (?, ?, ?, ?, ?)",
            (kind, mac, ip, reason.strip()[:300], now_iso()))
        self.conn.commit()
        return cur.lastrowid

    def suppressions(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM suppressions ORDER BY id")]

    def delete_suppression(self, rule_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM suppressions WHERE id = ?", (rule_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def match_suppression(self, alert: Alert) -> int | None:
        """ID of the first rule that silences this alert (and count the hit)."""
        mac, ip = alert.entity()
        for rule in self.suppressions():
            if rule["kind"] not in ("*", alert.kind):
                continue
            if rule["mac"] and rule["mac"] != mac:
                continue
            if rule["ip"] and rule["ip"] != ip:
                continue
            self.conn.execute("UPDATE suppressions SET hits = hits + 1, last_hit = ? WHERE id = ?",
                              (now_iso(), rule["id"]))
            self.conn.commit()
            return rule["id"]
        return None

    # -- meta ----------------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()


# --- Helpers ----------------------------------------------------------------
def _row_to_host(row: sqlite3.Row) -> Host:
    data = dict(row)
    data["trusted"] = bool(data["trusted"])
    data["online"] = bool(data["online"])
    return Host(**data)


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(severity=Severity(row["severity"]), kind=row["kind"],
                 message=row["message"], ts=row["ts"],
                 details=json.loads(row["details"]), id=row["id"],
                 status=row["status"], notes=row["notes"], updated_at=row["updated_at"])
