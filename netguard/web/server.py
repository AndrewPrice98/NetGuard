"""
Dashboard HTTP server — standard library only.

Serves a static single-page app plus a JSON API over the same SQLite
database the scanner writes. Each request opens its own Store, so it never
shares a connection with the monitor thread.

Security model (it's a security tool, so it should hold up to scrutiny):
    * binds to 127.0.0.1 by default
    * Host-header allow-list blocks DNS-rebinding attacks from web pages
    * state-changing requests need a custom header and a JSON content type,
      which a cross-site form or <img> can't send without a CORS preflight
      we never approve (CSRF)
    * optional token for when you deliberately expose it on the LAN
    * request bodies are size-capped; strict Content-Security-Policy; the UI
      builds DOM with textContent, so hostile hostnames can't inject script
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import csv
import hmac
import io
import json
import logging
import os
import re
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .. import __version__, discovery, oui, siem
from ..correlate import compression, find
from ..fingerprint import TYPE_LABELS
from ..incidents import incident_markdown, load_incidents, set_incident_status
from ..metrics import coverage, rule_fidelity, soc_metrics
from ..models import ALERT_STATUSES, OPEN_STATUSES, Host, PortState, Severity
from ..playbooks import PLAYBOOKS, TACTICS, playbook
from ..portscan import RISKY_PORTS
from ..report import build_report
from ..store import Store, iso_ago

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
MAX_BODY = 64 * 1024
MAC_PATH = r"(?P<mac>[0-9a-fA-F:-]{11,17})"
SEV_WEIGHT = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}


# --- Risk scoring -----------------------------------------------------------
def risk_score(host: Host, open_ports: list[PortState], open_alert_sevs: list[str]) -> int:
    """0-100 triage priority for a device. Transparent on purpose: the UI
    lists the factors, so an analyst can see *why* a device scores high."""
    return min(100, sum(f["points"] for f in risk_factors(host, open_ports, open_alert_sevs)))


def risk_factors(host: Host, open_ports: list[PortState], open_alert_sevs: list[str]) -> list[dict]:
    factors = []
    if not host.trusted:
        factors.append({"reason": "Not in the trusted baseline", "points": 30})
    alert_pts = min(50, sum(SEV_WEIGHT[s] for s in open_alert_sevs))
    if alert_pts:
        factors.append({"reason": f"{len(open_alert_sevs)} open alert(s)", "points": alert_pts})
    risky = sorted(p.port for p in open_ports if p.port in RISKY_PORTS)
    if risky:
        factors.append({"reason": f"Remote-access ports open: {', '.join(map(str, risky))}",
                        "points": min(20, 7 * len(risky))})
    if host.vendor == "randomized MAC" and not host.trusted:
        factors.append({"reason": "Randomized MAC (identity hidden)", "points": 5})
    return factors


def risk_level(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 15 else "low"


# --- Server -----------------------------------------------------------------
class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets a second process bind a port that is already
    # listening, so two copies would silently share it. Use exclusive binding
    # there instead; elsewhere SO_REUSEADDR only allows fast restarts.
    allow_reuse_address = os.name != "nt"

    def server_bind(self) -> None:
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address: tuple[str, int], db_path: Path | str,
                 monitor=None, token: str = "") -> None:
        super().__init__(address, Handler)
        self.db_path = db_path
        self.monitor = monitor
        self.token = token
        self.stopped_by_user = False


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


class RawResponse:
    """An endpoint result that isn't JSON (CSV/JSON downloads)."""

    def __init__(self, body: bytes, content_type: str, filename: str) -> None:
        self.body, self.content_type, self.filename = body, content_type, filename


# --- Handler ----------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "NetGuard"
    sys_version = ""

    ROUTES: list[tuple[str, re.Pattern, str]] = [(m, re.compile(p), n) for m, p, n in [
        ("GET", r"/api/status", "get_status"),
        ("GET", r"/api/overview", "get_overview"),
        ("GET", r"/api/hosts", "get_hosts"),
        ("GET", rf"/api/hosts/{MAC_PATH}", "get_host"),
        ("POST", rf"/api/hosts/{MAC_PATH}", "post_host"),
        ("POST", rf"/api/hosts/{MAC_PATH}/trust", "post_trust"),
        ("POST", rf"/api/hosts/{MAC_PATH}/untrust", "post_untrust"),
        ("DELETE", rf"/api/hosts/{MAC_PATH}", "delete_host"),
        ("GET", r"/api/alerts", "get_alerts"),
        ("GET", r"/api/alerts/(?P<id>\d+)", "get_alert"),
        ("POST", r"/api/alerts/(?P<id>\d+)/status", "post_alert_status"),
        ("POST", r"/api/alerts/(?P<id>\d+)/note", "post_alert_note"),
        ("POST", r"/api/alerts/(?P<id>\d+)/ack", "post_ack"),
        ("POST", r"/api/alerts/bulk", "post_bulk"),
        ("POST", r"/api/alerts/ack-all", "post_ack_all"),
        ("GET", r"/api/incidents", "get_incidents"),
        ("GET", r"/api/incidents/(?P<id>INC-\d{1,9})", "get_incident"),
        ("POST", r"/api/incidents/(?P<id>INC-\d{1,9})/status", "post_incident_status"),
        ("GET", r"/api/incidents/(?P<id>INC-\d{1,9})/report\.md", "get_incident_report"),
        ("GET", r"/api/metrics", "get_metrics"),
        ("GET", r"/api/detections", "get_detections"),
        ("GET", r"/api/validation", "get_validation"),
        ("GET", r"/api/events", "get_events"),
        ("GET", r"/api/suppressions", "get_suppressions"),
        ("POST", r"/api/suppressions", "post_suppression"),
        ("DELETE", r"/api/suppressions/(?P<id>\d+)", "delete_suppression"),
        ("GET", r"/api/playbooks", "get_playbooks"),
        ("GET", r"/api/export/alerts\.csv", "export_alerts_csv"),
        ("GET", r"/api/export/alerts\.json", "export_alerts_json"),
        ("GET", r"/api/export/alerts\.ecs\.ndjson", "export_alerts_ecs"),
        ("GET", r"/api/export/hosts\.csv", "export_hosts_csv"),
        ("POST", r"/api/scan", "post_scan"),
        ("POST", r"/api/shutdown", "post_shutdown"),
    ]]

    # -- plumbing ------------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        self.query = parse_qs(url.query)
        try:
            self._check_host()
            if url.path.startswith("/api/"):
                self._check_api_auth(method)
                self.body = self._read_body() if method == "POST" else {}
                path = unquote(url.path)  # e.g. MACs arrive as aa%3Abb%3A...
                for m, pattern, name in self.ROUTES:
                    if m == method and (match := pattern.fullmatch(path)):
                        with Store(self.server.db_path) as store:
                            result = getattr(self, name)(store, **match.groupdict())
                        if isinstance(result, RawResponse):
                            return self._send_raw(result)
                        return self._send_json(result)
                raise ApiError(HTTPStatus.NOT_FOUND, "No such endpoint")
            if method != "GET":
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "GET only")
            if url.path == "/report":
                return self._send_report()
            return self._send_static(url.path)
        except ApiError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except ValueError as exc:  # bad parameters from the client
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception:
            logger.exception("Request failed: %s %s", method, self.path)
            self._send_json({"error": "Internal error"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Body too large")
        if not length:
            return {}
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON only")
        try:
            data = json.loads(self.rfile.read(length))
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid JSON")
        if not isinstance(data, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Expected a JSON object")
        return data

    # -- security checks -----------------------------------------------------
    def _check_host(self) -> None:
        """Reject requests whose Host isn't us — defeats DNS rebinding."""
        if self.server.token:
            return  # the token is the guard when deliberately exposed
        raw = (self.headers.get("Host") or "").lower()
        host = raw.split("]")[0] + "]" if raw.startswith("[") else raw.split(":")[0]
        if host not in LOOPBACK_NAMES:
            raise ApiError(HTTPStatus.FORBIDDEN, "Bad Host header")

    def _token_ok(self, supplied: str | None) -> bool:
        return not self.server.token or hmac.compare_digest(
            (supplied or "").encode(), self.server.token.encode())

    def _check_api_auth(self, method: str) -> None:
        if not self._token_ok(self.headers.get("X-NetGuard-Token")):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Missing or wrong token")
        if method != "GET" and self.headers.get("X-NetGuard") != "1":
            raise ApiError(HTTPStatus.FORBIDDEN, "Missing X-NetGuard header")

    # -- responses -----------------------------------------------------------
    def _common_headers(self, csp: str = CSP) -> None:
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, data, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, raw: RawResponse) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", raw.content_type)
        self.send_header("Content-Length", str(len(raw.body)))
        self.send_header("Content-Disposition", f'attachment; filename="{raw.filename}"')
        self._common_headers()
        self.end_headers()
        self.wfile.write(raw.body)

    def _send_static(self, path: str) -> None:
        name = "index.html" if path in ("", "/") else path.removeprefix("/static/")
        # Whitelist: a bare file name that exists in the static dir. No
        # separators, so no path traversal.
        if not re.fullmatch(r"[\w-]+\.(html|js|css|svg)", name) or \
                not (STATIC_DIR / name).is_file():
            raise ApiError(HTTPStatus.NOT_FOUND, "Not found")
        body = (STATIC_DIR / name).read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", CONTENT_TYPES[Path(name).suffix])
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_report(self) -> None:
        if not self._token_ok(self._q("token")):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Missing or wrong token")
        days = self._q_int("days", 7, 1, 365)
        with Store(self.server.db_path) as store:
            body = build_report(store, days).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers(REPORT_CSP)
        self.end_headers()
        self.wfile.write(body)

    # -- parameter helpers ---------------------------------------------------
    def _q(self, key: str, default: str | None = None) -> str | None:
        return self.query.get(key, [default])[0]

    def _q_int(self, key: str, default: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(hi, int(self._q(key, str(default)))))
        except ValueError:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"{key} must be a number")

    def _q_severity(self) -> Severity:
        sev = (self._q("min") or "INFO").upper()
        if sev not in Severity.__members__:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Bad severity")
        return Severity[sev]

    def _q_statuses(self) -> list[str] | None:
        """status=open (default) | all | one or more comma-separated statuses."""
        raw = (self._q("status") or "open").lower()
        if raw == "all":
            return None
        if raw == "open":
            return list(OPEN_STATUSES)
        statuses = raw.split(",")
        if not set(statuses) <= set(ALERT_STATUSES):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Bad status")
        return statuses

    def _filtered_alerts(self, store: Store, default_limit: int = 200):
        days = self._q("days")
        return store.recent_alerts(
            limit=self._q_int("limit", default_limit, 1, 5000),
            min_severity=self._q_severity(),
            statuses=self._q_statuses(),
            since=iso_ago(days=int(days)) if days and days.isdigit() else None,
            kind=self._q("kind") or None,
            query=(self._q("q") or "").strip() or None,
            mac=self._q("mac") or None,
        )

    def _host_or_404(self, store: Store, mac: str) -> Host:
        host = store.get_host(discovery.normalize_mac(mac))
        if host is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"Unknown device {mac}")
        return host

    def _alert_or_404(self, store: Store, alert_id: str):
        alert = store.get_alert(int(alert_id))
        if alert is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "No such alert")
        return alert

    # -- serializers ---------------------------------------------------------
    @staticmethod
    def _open_alerts_by_mac(store: Store) -> dict[str, list[str]]:
        by_mac: dict[str, list[str]] = {}
        for a in store.recent_alerts(limit=5000, statuses=list(OPEN_STATUSES)):
            mac, _ = a.entity()
            if mac:
                by_mac.setdefault(mac, []).append(a.severity.name)
        return by_mac

    @staticmethod
    def _host_dict(h: Host, all_ports: list[PortState], open_ports: list[PortState],
                   alert_sevs: list[str]) -> dict:
        open_set = {p.port for p in open_ports}
        score = risk_score(h, open_ports, alert_sevs)
        return {
            "mac": h.mac, "ip": h.ip, "hostname": h.hostname, "vendor": h.vendor,
            "alias": h.alias, "notes": h.notes, "online": h.online,
            "type": h.device_type or "unknown",
            "type_label": TYPE_LABELS.get(h.device_type or "unknown", h.device_type),
            "trusted": h.trusted, "first_seen": h.first_seen, "last_seen": h.last_seen,
            "ports": [{"port": p.port, "service": p.service, "open": p.port in open_set,
                       "risky": p.port in RISKY_PORTS, "first_seen": p.first_seen,
                       "last_seen": p.last_seen} for p in all_ports],
            "open_alerts": len(alert_sevs),
            "risk": score, "risk_level": risk_level(score),
        }

    # -- endpoints: overview -------------------------------------------------
    def get_status(self, store: Store) -> dict:
        mon = self.server.monitor
        hosts = store.all_hosts()
        status = vars(mon.status).copy() if mon else {}
        # Devices first seen after this are "new". Older databases have no
        # marker, so fall back to the earliest sighting.
        baseline_at = store.get_meta("baseline_at") or min(
            (h.first_seen for h in hosts if h.first_seen), default="")
        incidents = load_incidents(store)
        open_inc = [i for i in incidents if i.is_open]
        return {
            "version": __version__,
            "monitoring": mon is not None,
            "baseline_at": baseline_at,
            "status": status,
            "alerts": store.alert_counts(unacked_only=True),
            "statuses": store.status_counts(),
            "incidents": {"open": len(open_inc), "total": len(incidents),
                          "critical": sum(i.severity >= Severity.CRITICAL for i in open_inc)},
            "hosts": len(hosts),
            "online": sum(h.online for h in hosts),
            "untrusted": sum(not h.trusted for h in hosts),
            "vendors": oui.registry_size(),
        }

    def get_overview(self, store: Store) -> dict:
        days = self._q_int("days", 14, 1, 90)
        names = {h.mac: h.alias or h.hostname or h.ip for h in store.all_hosts()}
        top_devices = [{**d, "name": names.get(d["mac"], d["mac"])}
                       for d in store.top_devices(days)]
        urgent = store.recent_alerts(limit=6, min_severity=Severity.HIGH,
                                     statuses=list(OPEN_STATUSES))
        incidents = load_incidents(store, max(days, 30))
        return {
            "series": store.alert_series(days),
            "top_kinds": [{**k, "title": playbook(k["kind"])["title"]}
                          for k in store.top_kinds(days)],
            "top_devices": top_devices,
            "urgent": [a.to_dict() for a in urgent],
            "incidents": [i.to_dict() for i in incidents if i.is_open][:6],
            "metrics": soc_metrics(store, 30),
            "events": [e.to_dict() for e in store.events(limit=10)],
        }

    # -- endpoints: hosts ----------------------------------------------------
    def get_hosts(self, store: Store) -> list[dict]:
        all_ports, open_ports = store.all_ports(), store.open_ports()
        alerts = self._open_alerts_by_mac(store)
        return [self._host_dict(h, all_ports.get(h.mac, []), open_ports.get(h.mac, []),
                                alerts.get(h.mac, []))
                for h in store.all_hosts()]

    def get_host(self, store: Store, mac: str) -> dict:
        h = self._host_or_404(store, mac)
        open_ports = store.open_ports().get(h.mac, [])
        sevs = self._open_alerts_by_mac(store).get(h.mac, [])
        data = self._host_dict(h, store.get_ports(h.mac), open_ports, sevs)
        data["risk_factors"] = risk_factors(h, open_ports, sevs)
        data["events"] = [e.to_dict() for e in store.events(limit=200, mac=h.mac)]
        data["alerts"] = [a.to_dict() for a in store.recent_alerts(limit=200, mac=h.mac)]
        return data

    def post_host(self, store: Store, mac: str) -> dict:
        h = self._host_or_404(store, mac)
        alias, notes = self.body.get("alias"), self.body.get("notes")
        for v in (alias, notes):
            if v is not None and not isinstance(v, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "alias/notes must be strings")
        store.update_host_info(h.mac, alias=alias, notes=notes)
        return {"ok": True}

    def post_trust(self, store: Store, mac: str) -> dict:
        store.set_trusted(self._host_or_404(store, mac).mac, True)
        return {"ok": True}

    def post_untrust(self, store: Store, mac: str) -> dict:
        store.set_trusted(self._host_or_404(store, mac).mac, False)
        return {"ok": True}

    def delete_host(self, store: Store, mac: str) -> dict:
        store.forget_host(self._host_or_404(store, mac).mac)
        return {"ok": True}

    # -- endpoints: alerts ---------------------------------------------------
    def get_alerts(self, store: Store) -> list[dict]:
        return [a.to_dict() for a in self._filtered_alerts(store)]

    def get_alert(self, store: Store, id: str) -> dict:
        a = self._alert_or_404(store, id)
        mac, ip = a.entity()
        host = store.get_host(mac) if mac else (store.get_host_by_ip(ip) if ip else None)
        related = []
        if host:
            related = [r.to_dict() for r in store.recent_alerts(limit=20, mac=host.mac,
                                                                statuses=None)
                       if r.id != a.id]
        incident = next((i for i in load_incidents(store, 90)
                         if any(x.id == a.id for x in i.alerts)), None)
        return {**a.to_dict(), "playbook": playbook(a.kind),
                "host": {"mac": host.mac, "ip": host.ip, "name": host.alias or host.hostname,
                         "trusted": host.trusted, "vendor": host.vendor} if host else None,
                "related": related,
                "history": store.alert_history(a.id),
                "incident": {"id": incident.id, "title": incident.pattern.title,
                             "severity": incident.severity.name, "status": incident.status,
                             "alert_count": len(incident.alerts)} if incident else None}

    def post_alert_status(self, store: Store, id: str) -> dict:
        status = self.body.get("status")
        if status not in ALERT_STATUSES:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"status must be one of {', '.join(ALERT_STATUSES)}")
        if not store.set_alert_status(int(id), status, str(self.body.get("note") or "")):
            raise ApiError(HTTPStatus.NOT_FOUND, "No such alert")
        return {"ok": True}

    def post_alert_note(self, store: Store, id: str) -> dict:
        note = str(self.body.get("note") or "").strip()
        if not note:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Empty note")
        if not store.add_alert_note(int(id), note):
            raise ApiError(HTTPStatus.NOT_FOUND, "No such alert")
        return {"ok": True}

    def post_ack(self, store: Store, id: str) -> dict:
        if not store.ack_alert(int(id)):
            raise ApiError(HTTPStatus.NOT_FOUND, "No such alert")
        return {"ok": True}

    def post_bulk(self, store: Store) -> dict:
        ids, status = self.body.get("ids"), self.body.get("status")
        if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids) or len(ids) > 1000:
            raise ApiError(HTTPStatus.BAD_REQUEST, "ids must be a list of alert ids")
        if status not in ALERT_STATUSES:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Bad status")
        return {"ok": True, "updated": store.set_status_bulk(ids, status)}

    def post_ack_all(self, store: Store) -> dict:
        return {"ok": True, "acked": store.ack_all()}

    # -- endpoints: incidents ------------------------------------------------
    def _incident_or_404(self, store: Store, incident_id: str):
        inc = find(load_incidents(store, self._q_int("days", 90, 1, 365)), incident_id)
        if inc is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "No such incident")
        return inc

    def get_incidents(self, store: Store) -> list[dict]:
        status = (self._q("status") or "open").lower()
        if status not in ("open", "closed", "all"):
            raise ApiError(HTTPStatus.BAD_REQUEST, "status must be open, closed or all")
        incidents = load_incidents(store, self._q_int("days", 30, 1, 365))
        if status != "all":
            incidents = [i for i in incidents if i.is_open == (status == "open")]
        return [i.to_dict() for i in incidents]

    def get_incident(self, store: Store, id: str) -> dict:
        inc = self._incident_or_404(store, id)
        data = inc.to_dict(full=True)
        data["alerts"] = [a.to_dict() for a in inc.alerts]
        data["events"] = [e.to_dict() for e in store.events(limit=300, mac=inc.mac)
                          if inc.first_ts <= e.ts <= inc.last_ts] if inc.mac else []
        return data

    def post_incident_status(self, store: Store, id: str) -> dict:
        status = self.body.get("status")
        if status not in ("new", "investigating", "resolved", "false_positive"):
            raise ApiError(HTTPStatus.BAD_REQUEST, "status must be new, investigating, "
                                                   "resolved or false_positive")
        inc = self._incident_or_404(store, id)
        updated = set_incident_status(store, inc, status, str(self.body.get("note") or "")[:1000])
        return {"ok": True, "updated": updated}

    def get_incident_report(self, store: Store, id: str) -> RawResponse:
        inc = self._incident_or_404(store, id)
        return RawResponse(incident_markdown(store, inc).encode(), "text/markdown; charset=utf-8",
                           f"{inc.id}.md")

    # -- endpoints: SOC metrics & detection engineering ------------------------
    def get_metrics(self, store: Store) -> dict:
        days = self._q_int("days", 30, 1, 365)
        alerts = store.recent_alerts(limit=20000, since=iso_ago(days=days), statuses=None)
        return {**soc_metrics(store, days),
                "correlation": compression(alerts, load_incidents(store, days))}

    def get_detections(self, store: Store) -> dict:
        from ..simulate import SCENARIOS
        return {
            "tactics": TACTICS,
            "coverage": coverage(),
            "rules": rule_fidelity(store, self._q_int("days", 30, 1, 365)),
            "scenarios": [{"name": s.name, "title": s.title, "technique": s.technique,
                           "description": s.description, "expect": sorted(s.expect),
                           "forbid": sorted(s.forbid), "gap": s.gap} for s in SCENARIOS],
        }

    def get_validation(self, store: Store) -> list[dict]:
        """Replay every attack simulation through the detectors right now."""
        from ..simulate import validate_all
        return [{"name": r.scenario.name, "passed": r.passed, "fired": sorted(r.fired),
                 "missing": sorted(r.missing), "unexpected": sorted(r.unexpected),
                 "packets": r.analysis.packets,
                 "alerts": [{"kind": a.kind, "severity": a.severity.name,
                             "frame": a.details.get("frame"), "message": a.message}
                            for a in r.analysis.alerts]}
                for r in validate_all()]

    # -- endpoints: activity, rules, reference -------------------------------
    def get_events(self, store: Store) -> list[dict]:
        days = self._q("days")
        mac = self._q("mac")
        return [e.to_dict() for e in store.events(
            limit=self._q_int("limit", 300, 1, 5000),
            mac=discovery.normalize_mac(mac) if mac else None,
            kind=self._q("kind") or None,
            since=iso_ago(days=int(days)) if days and days.isdigit() else None)]

    def get_suppressions(self, store: Store) -> list[dict]:
        return store.suppressions()

    def post_suppression(self, store: Store) -> dict:
        b = self.body
        kind = str(b.get("kind") or "").strip()
        if kind != "*" and kind not in PLAYBOOKS and not re.fullmatch(r"[a-z_]{2,40}", kind):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Unknown alert kind")
        mac = discovery.normalize_mac(b["mac"]) if b.get("mac") else ""
        ip = str(b.get("ip") or "").strip()
        if ip and not re.fullmatch(r"[\d.]{7,15}", ip):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Bad IP")
        rule_id = store.add_suppression(kind, mac, ip, str(b.get("reason") or ""))
        # Optionally close the alert that prompted the rule.
        if isinstance(b.get("alert_id"), int):
            store.set_alert_status(b["alert_id"], "false_positive",
                                   f"Suppression rule #{rule_id} created")
        return {"ok": True, "id": rule_id}

    def delete_suppression(self, store: Store, id: str) -> dict:
        if not store.delete_suppression(int(id)):
            raise ApiError(HTTPStatus.NOT_FOUND, "No such rule")
        return {"ok": True}

    def get_playbooks(self, store: Store) -> dict:
        return {kind: playbook(kind) for kind in PLAYBOOKS}

    # -- endpoints: export ---------------------------------------------------
    def export_alerts_csv(self, store: Store) -> RawResponse:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "timestamp_utc", "severity", "kind", "status", "device_mac",
                    "device_ip", "mitre", "message", "notes"])
        for a in self._filtered_alerts(store, default_limit=5000):
            mac, ip = a.entity()
            mitre = ";".join(t["id"] for t in playbook(a.kind)["mitre"])
            w.writerow([a.id, a.ts, a.severity.name, a.kind, a.status, mac, ip, mitre,
                        _csv_safe(a.message), _csv_safe(a.notes)])
        return RawResponse(out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                           "netguard-alerts.csv")

    def export_alerts_json(self, store: Store) -> RawResponse:
        data = [{**a.to_dict(), "mitre": [t["id"] for t in playbook(a.kind)["mitre"]]}
                for a in self._filtered_alerts(store, default_limit=5000)]
        return RawResponse(json.dumps(data, indent=2).encode(), "application/json",
                           "netguard-alerts.json")

    def export_alerts_ecs(self, store: Store) -> RawResponse:
        lines = [siem.format_alert(a, "ecs") for a in
                 reversed(self._filtered_alerts(store, default_limit=5000))]
        return RawResponse(("\n".join(lines) + "\n").encode(), "application/x-ndjson",
                           "netguard-alerts.ecs.ndjson")

    def export_hosts_csv(self, store: Store) -> RawResponse:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["ip", "mac", "alias", "hostname", "vendor", "type", "trusted", "online",
                    "risk", "open_ports", "first_seen_utc", "last_seen_utc", "notes"])
        for h in self.get_hosts(store):
            w.writerow([h["ip"], h["mac"], _csv_safe(h["alias"]), _csv_safe(h["hostname"]),
                        h["vendor"], h["type_label"], h["trusted"], h["online"], h["risk"],
                        " ".join(str(p["port"]) for p in h["ports"] if p["open"]),
                        h["first_seen"], h["last_seen"], _csv_safe(h["notes"])])
        return RawResponse(out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                           "netguard-devices.csv")

    # -- endpoints: actions --------------------------------------------------
    def post_scan(self, store: Store) -> dict:
        mon = self.server.monitor
        if mon is None:
            raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "Dashboard is in view-only mode")
        if not mon.trigger_scan():
            raise ApiError(HTTPStatus.CONFLICT, "A scan is already running")
        return {"ok": True}

    def post_shutdown(self, store: Store) -> dict:
        """The dashboard's Stop button. Same CSRF/token checks as every write,
        so a web page can't stop it. shutdown() waits for serve_forever() to
        return, so it must run on another thread; the response goes out first."""
        logger.warning("Shutdown requested from the dashboard")
        self.server.stopped_by_user = True
        threading.Timer(0.3, self.server.shutdown).start()
        return {"ok": True}


def _csv_safe(value: str) -> str:
    """Defuse CSV/formula injection: hostnames are attacker-controlled, and a
    cell starting with = + - @ would execute as a formula in Excel."""
    value = value or ""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


# --- Auto-reload ------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent.parent


def _source_stamp() -> float:
    """Newest modification time of NetGuard's Python source. (Static files
    are read from disk on every request, so they never need a restart.)"""
    return max((p.stat().st_mtime for p in PACKAGE_DIR.rglob("*.py") if p.is_file()), default=0.0)


def _watch_for_updates(httpd: "DashboardServer", reload_flag: threading.Event,
                       interval: float = 5.0) -> None:
    """A long-running background service (e.g. the Windows startup task)
    keeps whatever code it started with. Restart cleanly when files change."""
    start = _source_stamp()
    while not reload_flag.wait(interval):
        if _source_stamp() > start:
            logger.warning("NetGuard files changed on disk; restarting to load the new version")
            reload_flag.set()
            httpd.shutdown()


def _relaunch() -> None:
    """Start a fresh copy of this process (same arguments), then exit."""
    import os
    import subprocess
    import sys
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.Popen([sys.executable, "-m", "netguard", *sys.argv[1:]], cwd=os.getcwd(),
                     creationflags=flags, close_fds=True)
    os._exit(0)


# --- Finding, reusing and stopping a running copy ---------------------------
PORT_ATTEMPTS = 20


def running_netguard(port: int, token: str = "", timeout: float = 1.5) -> dict | None:
    """Status of the NetGuard listening on localhost:`port`, or None if the
    port is free or held by something else. {} if it's NetGuard but needs a token."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status",
                                 headers={"Host": "localhost", "X-NetGuard-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not (resp.headers.get("Server") or "").startswith("NetGuard"):
                return None
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {} if (exc.headers.get("Server") or "").startswith("NetGuard") else None
    except (OSError, ValueError):
        return None


def stop_running(port: int, token: str = "") -> bool:
    """Ask the NetGuard on localhost:`port` to shut down. True if it agreed."""
    import urllib.request
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/shutdown", data=b"", method="POST",
        headers={"Host": "localhost", "X-NetGuard": "1", "X-NetGuard-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except OSError:
        return False


def _bind(host: str, port: int, db_path, monitor, token: str, reuse_existing: bool,
          open_browser: bool) -> "DashboardServer | None":
    try:
        return DashboardServer((host, port), db_path, monitor, token)
    except OSError:
        pass
    existing = running_netguard(port, token)
    if reuse_existing and existing and existing.get("monitoring"):
        url = f"http://localhost:{port}/"
        print(f"NetGuard is already running and monitoring: {url}\n"
              f"(Use the Stop button in the dashboard, or `netguard stop --port {port}`, "
              "to shut it down.)", flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(url)
        return None
    for candidate in range(port + 1, port + PORT_ATTEMPTS):
        try:
            httpd = DashboardServer((host, candidate), db_path, monitor, token)
        except OSError:
            continue
        who = "another NetGuard" if existing is not None else "another program"
        print(f"Port {port} is in use by {who}; using port {candidate} instead.", flush=True)
        return httpd
    raise SystemExit(f"Ports {port}-{port + PORT_ATTEMPTS - 1} are all in use. "
                     "Pass --port to choose another.")


# --- Entry point ------------------------------------------------------------
def serve(db_path: Path | str, host: str = "127.0.0.1", port: int = 8000,
          monitor=None, token: str = "", open_browser: bool = False,
          reload: bool = False, reuse_existing: bool = False) -> None:
    """Run the dashboard (and the monitor loop, if given) until Ctrl+C or
    the dashboard's Stop button.

    If the port is busy: with `reuse_existing`, a NetGuard that is already
    monitoring there is simply opened; otherwise the next free port is used.
    """
    if host not in LOOPBACK_NAMES and not token:
        raise SystemExit("Refusing to listen on a non-loopback address without a token. "
                         "Set [web] token in netguard.toml or pass --token.")

    httpd = _bind(host, port, db_path, monitor, token, reuse_existing, open_browser)
    if httpd is None:
        return  # an existing NetGuard was opened instead
    reload_flag = threading.Event()
    if reload:
        threading.Thread(target=_watch_for_updates, args=(httpd, reload_flag),
                         name="netguard-reload", daemon=True).start()
    url = f"http://{'localhost' if host in LOOPBACK_NAMES else host}:{httpd.server_port}/"
    if token:
        url += f"#token={token}"

    if monitor:
        threading.Thread(target=monitor.run, name="netguard-monitor", daemon=True).start()
    print(f"NetGuard dashboard: {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if monitor:
            monitor.stop()
        httpd.server_close()  # free the port before the new copy binds it
    if httpd.stopped_by_user:
        print("Stopped from the dashboard.")
    elif reload_flag.is_set():
        _relaunch()
