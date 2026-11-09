"""
Self-contained HTML security report for the last N days.

One file, no external assets, print-friendly — "Print -> Save as PDF" in any
browser produces the PDF version. Every value from the network (hostnames
in particular, which come from reverse DNS) is HTML-escaped.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from . import __version__
from .fingerprint import TYPE_LABELS
from .models import Severity
from .store import Store, iso_ago

SEV_COLORS = {
    "CRITICAL": "#b42318", "HIGH": "#d92d20", "MEDIUM": "#b54708",
    "LOW": "#0e7490", "INFO": "#667085",
}

CSS = """
:root { --fg:#1d2939; --muted:#667085; --line:#e4e7ec; --bg:#fff; --soft:#f9fafb; }
* { box-sizing:border-box; }
body { font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; color:var(--fg);
       background:var(--bg); max-width:1000px; margin:32px auto; padding:0 20px; }
h1 { font-size:24px; margin:0; } h2 { font-size:17px; margin:32px 0 10px; }
.sub { color:var(--muted); margin:4px 0 24px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; }
.tile { border:1px solid var(--line); border-radius:10px; padding:12px 14px; background:var(--soft); }
.tile b { display:block; font-size:24px; } .tile span { color:var(--muted); font-size:12px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
.sev { font-weight:700; font-size:11px; padding:2px 7px; border-radius:99px; color:#fff; white-space:nowrap; }
.mono { font-family:ui-monospace,Consolas,monospace; font-size:12px; }
.empty { color:var(--muted); font-style:italic; }
.no { color:#d92d20; font-weight:600; }
footer { color:var(--muted); font-size:12px; margin:40px 0 20px; }
@media print { body { margin:0; } h2 { break-after:avoid; } tr { break-inside:avoid; } }
"""


def _sev(name: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLORS[name]}">{name}</span>'


def _ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def build_report(store: Store, days: int = 7) -> str:
    since = iso_ago(days=days)
    hosts = store.all_hosts()
    ports = store.all_ports()
    alerts = store.recent_alerts(limit=500, since=since)
    counts = store.alert_counts(unacked_only=False, since=since)
    # "New" means joined after the baseline, not "part of the baseline".
    baseline_at = store.get_meta("baseline_at") or min(
        (h.first_seen for h in hosts if h.first_seen), default="")
    new_hosts = [h for h in hosts if h.first_seen >= since and h.first_seen > baseline_at]
    untrusted = [h for h in hosts if not h.trusted]
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")

    tiles = [
        (len(hosts), "devices known"),
        (len(untrusted), "untrusted devices"),
        (len(new_hosts), f"new in {days} days"),
        (counts["CRITICAL"] + counts["HIGH"], "critical + high alerts"),
        (sum(counts.values()), "alerts in total"),
    ]
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>NetGuard report</title><style>{CSS}</style></head><body>",
        "<h1>NetGuard security report</h1>",
        f"<p class='sub'>Last {days} days &middot; generated {escape(generated)}</p>",
        "<div class='tiles'>",
        *(f"<div class='tile'><b>{n}</b><span>{escape(label)}</span></div>" for n, label in tiles),
        "</div>",
    ]

    # Alerts by severity
    out.append("<h2>Alerts by severity</h2><table><tr>")
    out += [f"<th>{_sev(s.name)}</th>" for s in reversed(Severity)]
    out.append("</tr><tr>")
    out += [f"<td><b>{counts[s.name]}</b></td>" for s in reversed(Severity)]
    out.append("</tr></table>")

    # New devices
    out.append(f"<h2>New devices ({len(new_hosts)})</h2>")
    if new_hosts:
        out.append("<table><tr><th>First seen</th><th>IP</th><th>MAC</th><th>Name</th>"
                   "<th>Vendor</th><th>Trusted</th></tr>")
        for h in sorted(new_hosts, key=lambda h: h.first_seen):
            out.append(
                f"<tr><td>{_ts(h.first_seen)}</td><td class='mono'>{escape(h.ip)}</td>"
                f"<td class='mono'>{escape(h.mac)}</td><td>{escape(h.hostname)}</td>"
                f"<td>{escape(h.vendor)}</td>"
                f"<td>{'yes' if h.trusted else '<span class=no>NO</span>'}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class='empty'>No new devices.</p>")

    # Alert log
    out.append(f"<h2>Alerts ({len(alerts)})</h2>")
    if alerts:
        out.append("<table><tr><th>Time</th><th>Severity</th><th>Type</th><th>Detail</th></tr>")
        for a in alerts:
            out.append(f"<tr><td style='white-space:nowrap'>{_ts(a.ts)}</td>"
                       f"<td>{_sev(a.severity.name)}</td><td class='mono'>{escape(a.kind)}</td>"
                       f"<td>{escape(a.message)}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class='empty'>No alerts in this period.</p>")

    # Inventory
    out.append(f"<h2>Device inventory ({len(hosts)})</h2>")
    out.append("<table><tr><th>IP</th><th>MAC</th><th>Type</th><th>Name / vendor</th>"
               "<th>Open ports</th><th>Last seen</th><th>Trusted</th></tr>")
    for h in hosts:
        plist = ", ".join(f"{p.port}" + (f"/{p.service}" if p.service else "")
                          for p in ports.get(h.mac, []))
        name = " · ".join(x for x in (h.hostname, h.vendor) if x)
        out.append(
            f"<tr><td class='mono'>{escape(h.ip)}</td><td class='mono'>{escape(h.mac)}</td>"
            f"<td>{escape(TYPE_LABELS.get(h.device_type, h.device_type or '—'))}</td>"
            f"<td>{escape(name)}</td><td class='mono'>{escape(plist)}</td>"
            f"<td>{_ts(h.last_seen)}</td>"
            f"<td>{'yes' if h.trusted else '<span class=no>NO</span>'}</td></tr>")
    out.append("</table>")

    out.append(f"<footer>NetGuard {__version__}</footer></body></html>")
    return "\n".join(out)
