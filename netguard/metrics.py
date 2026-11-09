"""
SOC metrics: how fast alerts are handled, and how good each detection is.

Response times come from the alert audit trail (store.alert_history):

    time to triage   (MTTA)  alert raised -> first move out of "new"
    time to resolve  (MTTR)  alert raised -> first close (resolved / false positive)

Medians are reported alongside means because one alert left open over a
weekend shouldn't hide that the typical alert was handled in minutes.

Rule fidelity is the detection-engineering view: for every rule, how many
of its closed alerts were real (resolved) versus false positives. A rule
with a poor true-positive rate is a tuning candidate: tighten its logic or
add a suppression rule for the known-benign source.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

from collections import Counter
from datetime import datetime
from statistics import mean, median

from .models import OPEN_STATUSES, Alert, Severity
from .playbooks import DETECTIONS, PLAYBOOKS, playbook, tactic_index
from .store import Store, iso_ago

CLOSED = ("resolved", "false_positive")


def _secs(a: str, b: str) -> float | None:
    try:
        return max(0.0, (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds())
    except ValueError:
        return None


def response_times(alert: Alert, history: list[dict]) -> tuple[float | None, float | None]:
    """(seconds to triage, seconds to close) for one alert; None if not yet."""
    tta = ttr = None
    for h in history:
        if h["from_status"] == "":
            continue  # creation
        if tta is None and h["from_status"] == "new":
            tta = _secs(alert.ts, h["ts"])
        if ttr is None and h["to_status"] in CLOSED:
            ttr = _secs(alert.ts, h["ts"])
    if ttr is not None and tta is None:
        tta = ttr  # closed straight from "new": triaged at the same moment
    return tta, ttr


def _summary(values: list[float]) -> dict:
    if not values:
        return {"median": None, "mean": None, "n": 0}
    return {"median": round(median(values)), "mean": round(mean(values)), "n": len(values)}


def soc_metrics(store: Store, days: int = 30) -> dict:
    """Queue health and response times over the last `days`."""
    since = iso_ago(days=days)
    alerts = [a for a in store.recent_alerts(limit=20000, since=since, statuses=None)
              if a.status != "suppressed"]
    history = store.all_history(since)
    tta, ttr = [], []
    by_sev: dict[str, list[float]] = {}
    for a in alerts:
        t_a, t_r = response_times(a, history.get(a.id, []))
        if t_a is not None:
            tta.append(t_a)
            by_sev.setdefault(a.severity.name, []).append(t_a)
        if t_r is not None:
            ttr.append(t_r)

    open_alerts = [a for a in alerts if a.status in OPEN_STATUSES]
    closed = [a for a in alerts if a.status in CLOSED]
    fps = sum(a.status == "false_positive" for a in closed)
    oldest = min((a.ts for a in open_alerts), default="")
    return {
        "days": days,
        "alerts": len(alerts),
        "open": len(open_alerts),
        "closed": len(closed),
        "false_positive_rate": round(fps / len(closed), 3) if closed else None,
        "mtta": _summary(tta),
        "mttr": _summary(ttr),
        "mtta_by_severity": {s.name: _summary(by_sev.get(s.name, []))
                             for s in reversed(Severity) if s.name in by_sev},
        "oldest_open": oldest,
        "suppressed": store.status_counts().get("suppressed", 0),
    }


def rule_fidelity(store: Store, days: int = 30) -> list[dict]:
    """Per-detection volume and outcome, every rule listed (zeros included)."""
    since = iso_ago(days=days)
    rows: dict[str, dict] = {
        kind: {"kind": kind, "alerts": 0, "open": 0, "resolved": 0, "false_positive": 0,
               "suppressed": 0, "_ttr": []}
        for kind in PLAYBOOKS
    }
    history = store.all_history(since)
    for a in store.recent_alerts(limit=20000, since=since, statuses=None):
        r = rows.setdefault(a.kind, {"kind": a.kind, "alerts": 0, "open": 0, "resolved": 0,
                                     "false_positive": 0, "suppressed": 0, "_ttr": []})
        r["alerts"] += 1
        if a.status in OPEN_STATUSES:
            r["open"] += 1
        elif a.status in r:
            r[a.status] += 1
        _, t_r = response_times(a, history.get(a.id, []))
        if t_r is not None:
            r["_ttr"].append(t_r)

    rules = Counter(s["kind"] for s in store.suppressions())

    out = []
    for kind, r in rows.items():
        pb = playbook(kind)
        closed = r["resolved"] + r["false_positive"]
        ttr = r.pop("_ttr")
        out.append({
            **r,
            "title": pb["title"], "stage": pb.get("stage", ""), "tactic": pb["tactic"],
            "techniques": [t["id"] for t in pb["mitre"]],
            "source": pb.get("source", ""), "default_severity": pb.get("default_severity", ""),
            "validated_by": pb.get("validated_by", ""),
            "tp_rate": round(r["resolved"] / closed, 3) if closed else None,
            "median_ttr": round(median(ttr)) if ttr else None,
            "suppression_rules": rules[kind],
        })
    out.sort(key=lambda r: (-r["alerts"], r["title"]))
    return out


def coverage() -> list[dict]:
    """ATT&CK techniques this sensor can detect, grouped by tactic."""
    by_tactic: dict[str, dict[str, dict]] = {}
    for kind in DETECTIONS:
        pb = playbook(kind)
        tactics = [t.strip() for t in pb["tactic"].split("/") if t.strip()]
        for tactic in tactics:
            for t in pb["mitre"]:
                cell = by_tactic.setdefault(tactic, {}).setdefault(
                    t["id"], {**t, "rules": []})
                if kind not in cell["rules"]:
                    cell["rules"].append(kind)
    return [{"tactic": tactic, "techniques": sorted(cells.values(), key=lambda c: c["id"])}
            for tactic, cells in sorted(by_tactic.items(), key=lambda kv: tactic_index(kv[0]))]
