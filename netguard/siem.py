"""
SIEM output formats.

A sensor is only useful in a SOC if its alerts land where analysts already
work. NetGuard can emit each alert as:

    json   NetGuard's own schema (Alert.to_dict)
    ecs    Elastic Common Schema 8.x, for Elastic / OpenSearch / any ECS pipeline
    cef    ArcSight Common Event Format, understood by Splunk, QRadar, Sentinel, ArcSight

via the JSON-lines log ([alerts] log + log_format), a syslog sink
([[notify]] type = "syslog"), or `netguard export` for history.

Both mappings carry the MITRE ATT&CK technique and tactic, so detections
can be pivoted on by technique in the SIEM, not just by NetGuard rule name.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import json
from datetime import datetime

from . import __version__
from .models import Alert, Severity
from .playbooks import playbook

FORMATS = ("json", "ecs", "cef")

# ECS event.severity is numeric, free scale; CEF severity is 0-10.
ECS_SEVERITY = {Severity.INFO: 1, Severity.LOW: 21, Severity.MEDIUM: 47,
                Severity.HIGH: 73, Severity.CRITICAL: 99}
CEF_SEVERITY = {Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5,
                Severity.HIGH: 8, Severity.CRITICAL: 10}


def _ecs_mac(mac: str) -> str:
    """ECS wants MACs upper-case and hyphen-separated: AA-BB-CC-DD-EE-FF."""
    return mac.upper().replace(":", "-")


# --- ECS --------------------------------------------------------------------
def to_ecs(alert: Alert) -> dict:
    pb = playbook(alert.kind)
    mac, ip = alert.entity()
    tactics = [t.strip() for t in pb["tactic"].split("/") if t.strip()]
    doc: dict = {
        "@timestamp": alert.ts,
        "message": alert.message,
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info"],
            "module": "netguard",
            "dataset": "netguard.alert",
            "provider": "netguard",
            "action": alert.kind,
            "severity": ECS_SEVERITY[alert.severity],
            "id": str(alert.id) if alert.id is not None else None,
        },
        "rule": {"id": alert.kind, "name": pb["title"], "category": pb.get("stage") or None,
                 "ruleset": "netguard", "description": pb["summary"] or None},
        "observer": {"type": "ids", "vendor": "NetGuard", "product": "NetGuard",
                     "version": __version__},
        "log": {"level": alert.severity.name.lower()},
        "netguard": {"severity": alert.severity.name, "status": alert.status,
                     "details": alert.details},
    }
    if pb["mitre"]:
        doc["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": [{"id": t["id"].split(".")[0], "reference": t["url"],
                           "name": t["name"].split(":")[0]} for t in pb["mitre"]],
            "tactic": {"name": tactics},
        }
        subs = [t for t in pb["mitre"] if "." in t["id"]]
        if subs:
            doc["threat"]["technique"][0]["subtechnique"] = [
                {"id": t["id"], "name": t["name"], "reference": t["url"]} for t in subs]
    source = {}
    if ip:
        source["ip"] = ip
    if mac:
        source["mac"] = _ecs_mac(mac)
    if source:
        doc["source"] = source
    if alert.kind == "new_port" and alert.details.get("port"):
        doc["destination"] = {"port": alert.details["port"], **({"ip": ip} if ip else {})}
        doc["network"] = {"transport": alert.details.get("proto", "tcp")}
    _drop_none(doc)
    return doc


def _drop_none(d: dict) -> None:
    for k in [k for k, v in d.items() if v is None]:
        del d[k]
    for v in d.values():
        if isinstance(v, dict):
            _drop_none(v)


# --- CEF --------------------------------------------------------------------
def _cef_header(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(value) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", "\\n").replace("\r", "\\r"))


def to_cef(alert: Alert) -> str:
    pb = playbook(alert.kind)
    mac, ip = alert.entity()
    ext: dict[str, object] = {}
    try:
        ext["rt"] = int(datetime.fromisoformat(alert.ts).timestamp() * 1000)
    except ValueError:
        pass
    if ip:
        ext["src"] = ip
    if mac:
        ext["smac"] = mac
    if alert.kind == "new_port" and alert.details.get("port"):
        ext["dpt"] = alert.details["port"]
        ext["proto"] = alert.details.get("proto", "tcp").upper()
    ext["msg"] = alert.message
    ext["cat"] = pb.get("stage") or pb["tactic"] or "netguard"
    if alert.id is not None:
        ext["externalId"] = alert.id
    if pb["mitre"]:
        ext["cs1Label"] = "mitreTechnique"
        ext["cs1"] = ",".join(t["id"] for t in pb["mitre"])
    ext["cs2Label"] = "status"
    ext["cs2"] = alert.status
    header = "|".join(_cef_header(x) for x in (
        "CEF:0", "NetGuard", "NetGuard", __version__, alert.kind, pb["title"],
        CEF_SEVERITY[alert.severity]))
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items())


# --- Dispatch ---------------------------------------------------------------
def format_alert(alert: Alert, fmt: str = "json") -> str:
    """One line, ready for a log file or a syslog message."""
    if fmt == "json":
        return json.dumps(alert.to_dict())
    if fmt == "ecs":
        return json.dumps(to_ecs(alert))
    if fmt == "cef":
        return to_cef(alert)
    raise ValueError(f"Unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
