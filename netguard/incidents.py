"""
Incident case handling on top of correlate.py: loading incidents from the
store, acting on them, and drafting the incident report.

The Markdown report follows the structure most IR teams use (summary,
scope, timeline, indicators, ATT&CK mapping, actions, analyst notes), so
it can be pasted into a ticket or handed to whoever owns the network.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import re
from datetime import datetime

from . import __version__
from .correlate import Incident, correlate
from .metrics import response_times
from .models import OPEN_STATUSES
from .playbooks import playbook
from .store import Store, iso_ago, now_iso


def load_incidents(store: Store, days: int = 30) -> list[Incident]:
    alerts = store.recent_alerts(limit=20000, since=iso_ago(days=days), statuses=None)
    return correlate(alerts, store.all_hosts())


def set_incident_status(store: Store, inc: Incident, status: str, note: str = "") -> int:
    """Apply a triage action to the incident's alerts.

    Opening actions (new/investigating) touch every alert; closing actions
    only touch alerts that are still open, so an alert already closed as a
    false positive isn't silently re-labelled as resolved.
    """
    targets = inc.alerts if status in OPEN_STATUSES else \
        [a for a in inc.alerts if a.status in OPEN_STATUSES]
    tagged = f"[{inc.id}] {note}".strip() if note.strip() else ""
    return sum(store.set_alert_status(a.id, status, tagged) for a in targets)


def _fmt(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return ts


def _dur(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    m = int(seconds // 60)
    return f"{m // 60}h {m % 60:02d}m" if m >= 60 else f"{m}m"


def _md(text: str) -> str:
    """Hostnames and messages are attacker-influenced: neutralize Markdown/HTML."""
    out = str(text).replace("\\", "\\\\")
    for ch in "`*_[]<>|#":
        out = out.replace(ch, "\\" + ch)
    return " ".join(out.split())


def incident_markdown(store: Store, inc: Incident) -> str:
    d = inc.to_dict(full=True)
    who = _md(inc.name or inc.ip or inc.mac)
    iocs = d["indicators"]
    history = {a.id: store.alert_history(a.id) for a in inc.alerts}
    first_triage = [t for a in inc.alerts if (t := response_times(a, history[a.id])[0]) is not None]
    closes = [t for a in inc.alerts if (t := response_times(a, history[a.id])[1]) is not None]

    lines = [
        f"# {inc.id}: {_md(inc.pattern.title)}",
        "",
        "| | |",
        "|---|---|",
        f"| **Severity** | {inc.severity.name}{' (escalated: multi-stage)' if inc.escalated else ''} |",
        f"| **Status** | {inc.status.replace('_', ' ')} |",
        f"| **Affected / source device** | {who} · `{inc.ip or '-'}` · `{inc.mac or '-'}` "
        f"({'trusted' if inc.trusted else 'not in baseline' if inc.trusted is False else 'unknown'}) |",
        f"| **First activity** | {_fmt(inc.first_ts)} |",
        f"| **Last activity** | {_fmt(inc.last_ts)} |",
        f"| **Alerts** | {len(inc.alerts)} ({d['open_alerts']} open) |",
        f"| **Time to first triage** | {_dur(min(first_triage) if first_triage else None)} |",
        f"| **Time to close** | {_dur(max(closes) if closes and not inc.is_open else None)} |",
        "",
        "## Summary",
        "",
        _md(inc.narrative()),
        "",
        "## ATT&CK mapping",
        "",
        "| Tactic (as reached) | Technique |",
        "|---|---|",
    ]
    seen = set()
    for a in inc.alerts:
        pb = playbook(a.kind)
        for t in pb["mitre"]:
            key = (pb.get("stage", ""), t["id"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"| {pb.get('stage') or '-'} | [{t['id']}]({t['url']}) {t['name']} |")

    lines += ["", "## Timeline", "", "| Time (UTC) | Severity | Detection | Detail | Status |",
              "|---|---|---|---|---|"]
    for a in inc.alerts:
        evidence = f" (frame {a.details['frame']} of {_md(a.details.get('evidence', 'capture'))})" \
            if "frame" in a.details else ""
        lines.append(f"| {_fmt(a.ts)[:19]} | {a.severity.name} | {_md(playbook(a.kind)['title'])} "
                     f"| {_md(a.message)}{evidence} | {a.status.replace('_', ' ')} |")
    events = [e for e in store.events(limit=500, mac=inc.mac) if inc.first_ts <= e.ts <= inc.last_ts] \
        if inc.mac else []
    if events:
        lines += ["", "Related network activity:", ""]
        lines += [f"- {_fmt(e.ts)[:19]}: {_md(e.message)}" for e in reversed(events)]

    lines += ["", "## Indicators", ""]
    if iocs["macs"]:
        lines.append("- MAC: " + ", ".join(f"`{m}`" for m in iocs["macs"]))
    if iocs["ips"]:
        lines.append("- IPv4: " + ", ".join(f"`{i}`" for i in iocs["ips"]))
    if iocs["ports"]:
        lines.append("- Listening ports: " + ", ".join(f"`{p}`" for p in iocs["ports"]))
    if iocs["impersonated"]:
        lines.append("- Impersonated (victim) addresses: "
                     + ", ".join(f"`{i}`" for i in iocs["impersonated"]))

    lines += ["", "## Recommended response", ""]
    lines += [f"{n}. {step}" for n, step in enumerate(inc.pattern.response, 1)]

    notes = []
    for a in inc.alerts:
        for line in a.notes.splitlines():
            m = re.match(r"^\[([^\]]+)\] (.*)$", line)
            if m:
                notes.append((m.group(1), a.id, m.group(2)))
            elif line.strip():
                notes.append(("", a.id, line))
    lines += ["", "## Analyst notes", ""]
    lines += [f"- {_fmt(ts)[:19] or '-'} (alert #{aid}): {_md(text)}"
              for ts, aid, text in sorted(notes)] or ["- none recorded"]

    trail = sorted(((h["ts"], a.id, h) for a in inc.alerts for h in history[a.id]
                    if h["from_status"]), key=lambda x: x[0])
    if trail:
        lines += ["", "## Audit trail", ""]
        lines += [f"- {_fmt(ts)[:19]}: alert #{aid} {h['from_status']} → {h['to_status']}"
                  for ts, aid, h in trail]

    lines += ["", "---", f"*Drafted by NetGuard {__version__} on {_fmt(now_iso())}. "
              "Generated from detection data; verify before distribution.*", ""]
    return "\n".join(lines)
