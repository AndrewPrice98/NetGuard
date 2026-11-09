"""
Incident correlation: turn a stream of alerts into a short list of cases.

An analyst shouldn't have to notice that "new device joined", "port scan",
"new listening service" and "gateway ARP spoofing" all came from the same
laptop within the same hour. This module does that grouping and says what
the sequence most likely means.

How alerts become incidents
    1. Each alert is attributed to an entity: the device MAC it names, or,
       for alerts that only carry an IP (a port scan's source), the MAC
       that held that IP in the inventory.
    2. One entity's alerts are split into clusters wherever the gap between
       two consecutive alerts is longer than the correlation window
       (24 h by default).
    3. A cluster is promoted to an incident when it is worth a case: any
       HIGH/CRITICAL alert, or two or more alerts of MEDIUM and above.
       Low-level noise stays in the alert queue.
    4. The cluster is matched against attack patterns (most specific
       first) for a title, a narrative and containment steps, and its
       severity is escalated one level when it spans three or more
       ATT&CK tactics: a multi-stage intrusion is worse than its parts.

Incidents are derived, not stored: they are recomputed from the alert
table, so they can never drift out of sync with it. Their state is their
alerts' state, and actions on an incident are applied to its alerts. An
incident's ID comes from its first alert, so it is stable as it grows.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import OPEN_STATUSES, Alert, Host, Severity
from .playbooks import playbook, tactic_index
from .portscan import RISKY_PORTS

DEFAULT_WINDOW = timedelta(hours=24)
SPOOF_KINDS = {"gateway_arp_spoof", "arp_spoof", "gateway_mac_changed", "arp_mismatch"}


# --- Attack patterns ----------------------------------------------------------
@dataclass(frozen=True)
class Pattern:
    """A named alert sequence. `match` sees the set of alert kinds and the
    cluster's alerts; the first matching pattern names the incident."""

    key: str
    title: str
    assessment: str
    response: tuple[str, ...]
    match: object  # Callable[[set[str], list[Alert]], bool]


def _risky_port(alerts: list[Alert]) -> bool:
    return any(a.kind == "new_port" and a.details.get("port") in RISKY_PORTS for a in alerts)


PATTERNS: list[Pattern] = [
    Pattern(
        "aitm_chain", "Adversary-in-the-middle attack chain",
        "A device staged an interception attack end to end: it got onto the network, "
        "mapped it, and then poisoned ARP or DHCP so that other devices' traffic "
        "flows through it. Treat as an active compromise of the local network.",
        ("Isolate the device now: block its MAC on the router or pull its switch port.",
         "Flush ARP caches on clients and confirm the gateway MAC matches the router.",
         "Rotate the Wi-Fi password and any credentials used since the first alert.",
         "Preserve evidence: export the incident report and any packet captures."),
        lambda k, a: bool(k & (SPOOF_KINDS | {"rogue_dhcp"})) and bool(k & {"new_host", "port_scan"}),
    ),
    Pattern(
        "aitm", "Adversary-in-the-middle activity",
        "Traffic interception in progress or attempted (ARP cache poisoning or a "
        "rogue DHCP server). Everything sent across the LAN during the window may "
        "have been read or modified.",
        ("Identify and disconnect the device that owns the spoofing MAC / DHCP server.",
         "Flush ARP caches; renew DHCP leases and verify gateway and DNS settings.",
         "Rotate credentials used during the window."),
        lambda k, a: bool(k & (SPOOF_KINDS | {"rogue_dhcp"})),
    ),
    Pattern(
        "recon_to_exposure", "Reconnaissance followed by service exposure",
        "A device scanned the network and then opened listening services. Scanning "
        "followed by a new remote-access or backdoor port is a classic foothold sequence.",
        ("Isolate the device and identify the process behind each new port.",
         "Check the scanned hosts for signs of follow-on access."),
        lambda k, a: {"port_scan", "new_port"} <= k,
    ),
    Pattern(
        "rogue_remote_access", "Unauthorized device exposing remote access",
        "A device that is not in the baseline joined and is listening on a remote-access "
        "port (SSH, RDP, VNC, SMB, ...). Either an unmanaged gadget or an implant "
        "waiting for a connection.",
        ("Identify the owner. If nobody claims it, block it and rotate the Wi-Fi password.",
         "If it is legitimate, trust it and disable the service if it isn't needed."),
        lambda k, a: "new_host" in k and _risky_port(a),
    ),
    Pattern(
        "recon", "Network reconnaissance",
        "Systematic probing of services. Usually the step before exploitation; sometimes "
        "an authorized scanner that needs a suppression rule.",
        ("Confirm whether the source is an authorized scanner.",
         "If not, isolate it and review what it can reach."),
        lambda k, a: "port_scan" in k,
    ),
    Pattern(
        "service_drift", "Unexpected service exposure",
        "A device started listening on new ports. Check whether software was installed "
        "or a setting changed.",
        ("Identify the process behind the port; disable or firewall it if unneeded.",),
        lambda k, a: "new_port" in k,
    ),
    Pattern(
        "unknown_device", "Unknown device on the network",
        "A device outside the baseline joined and drew attention.",
        ("Identify the owner; trust it or block it.",),
        lambda k, a: "new_host" in k,
    ),
]

FALLBACK = Pattern("activity", "Correlated suspicious activity",
                   "Several related alerts on one device.",
                   ("Review each alert's playbook.",), lambda k, a: True)


# --- Incident ---------------------------------------------------------------
@dataclass
class Incident:
    id: str
    pattern: Pattern
    mac: str
    ip: str
    name: str
    trusted: bool | None
    alerts: list[Alert] = field(default_factory=list)  # oldest first
    severity: Severity = Severity.INFO
    escalated: bool = False

    # -- derived -------------------------------------------------------------
    @property
    def first_ts(self) -> str:
        return self.alerts[0].ts

    @property
    def last_ts(self) -> str:
        return self.alerts[-1].ts

    @property
    def tactics(self) -> list[str]:
        """Distinct ATT&CK tactics, in the order the attack reached them."""
        seen: list[str] = []
        for a in self.alerts:
            stage = playbook(a.kind).get("stage", "")
            if stage and stage not in seen:
                seen.append(stage)
        return seen

    @property
    def techniques(self) -> list[dict]:
        out: dict[str, dict] = {}
        for a in self.alerts:
            for t in playbook(a.kind)["mitre"]:
                out.setdefault(t["id"], t)
        return list(out.values())

    @property
    def status(self) -> str:
        """new | investigating (any member open) | resolved | false_positive."""
        statuses = {a.status for a in self.alerts}
        if "investigating" in statuses:
            return "investigating"
        if "new" in statuses:
            return "new"
        closed = statuses - {"suppressed"}
        return "false_positive" if closed == {"false_positive"} else "resolved"

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES

    def indicators(self) -> dict[str, list]:
        """IOCs worth handing to a firewall or a threat-intel lookup.

        In spoofing alerts the `ip` is the address being *impersonated* (the
        victim), not the attacker's, so it is reported separately.
        """
        macs, ips, ports, victims = {self.mac} - {""}, {self.ip} - {""}, set(), set()
        for a in self.alerts:
            d = a.details
            for k in ("mac", "claimed_mac", "new_mac", "server_mac"):
                if d.get(k):
                    macs.add(d[k])
            for k in ("ip", "src", "server_ip"):
                if d.get(k):
                    (victims if k == "ip" and a.kind in SPOOF_KINDS else ips).add(d[k])
            if a.kind == "new_port" and d.get("port"):
                ports.add(f"{d.get('proto', 'tcp')}/{d['port']}")
        return {"macs": sorted(macs), "ips": sorted(ips - victims), "ports": sorted(ports),
                "impersonated": sorted(victims)}

    def narrative(self) -> str:
        """One paragraph an analyst can paste into a ticket."""
        who = f"{self.name} ({self.ip or self.mac})" if self.name else (self.ip or self.mac)
        trust = "" if self.trusted is None else (" a trusted device," if self.trusted
                                                  else " a device outside the baseline,")
        span = _duration(self.first_ts, self.last_ts)
        n = len(self.alerts)
        text = (f"{who},{trust} raised {n} alert{'s' if n != 1 else ''}"
                f"{f' over {span}' if span else ''}")
        if self.tactics:
            text += f" spanning {len(self.tactics)} ATT&CK tactic{'s' if len(self.tactics) != 1 else ''}: " \
                    + " → ".join(self.tactics)
        text += ". " + self.pattern.assessment
        if self.escalated:
            text += " Severity was escalated because the activity spans multiple attack stages."
        return text

    def to_dict(self, full: bool = False) -> dict:
        data = {
            "id": self.id, "title": self.pattern.title, "pattern": self.pattern.key,
            "severity": self.severity.name, "level": int(self.severity),
            "escalated": self.escalated, "status": self.status, "open": self.is_open,
            "mac": self.mac, "ip": self.ip, "name": self.name, "trusted": self.trusted,
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "alert_count": len(self.alerts), "alert_ids": [a.id for a in self.alerts],
            "open_alerts": sum(a.status in OPEN_STATUSES for a in self.alerts),
            "tactics": self.tactics,
            "techniques": [t["id"] for t in self.techniques],
        }
        if full:
            data.update({
                "narrative": self.narrative(),
                "assessment": self.pattern.assessment,
                "response": list(self.pattern.response),
                "technique_details": self.techniques,
                "indicators": self.indicators(),
                "chain": [{"alert_id": a.id, "ts": a.ts, "kind": a.kind, "severity": a.severity.name,
                           "title": playbook(a.kind)["title"], "stage": playbook(a.kind).get("stage", ""),
                           "techniques": [t["id"] for t in playbook(a.kind)["mitre"]],
                           "message": a.message, "status": a.status} for a in self.alerts],
            })
        return data


# --- Correlation ------------------------------------------------------------
def correlate(alerts: list[Alert], hosts: list[Host],
              window: timedelta = DEFAULT_WINDOW) -> list[Incident]:
    """Group alerts into incidents. Pure: no database, no clock."""
    by_mac = {h.mac: h for h in hosts}
    mac_for_ip = {h.ip: h.mac for h in sorted(hosts, key=lambda h: h.last_seen) if h.ip}

    groups: dict[str, list[Alert]] = {}
    for a in alerts:
        if a.status == "suppressed" or a.severity <= Severity.INFO:
            continue
        mac, ip = a.entity()
        key = mac or mac_for_ip.get(ip) or (f"ip:{ip}" if ip else f"alert:{a.id}")
        groups.setdefault(key, []).append(a)

    incidents = []
    for key, members in groups.items():
        members.sort(key=lambda a: (a.ts, a.id or 0))
        for cluster in _split(members, window):
            if not _worth_an_incident(cluster):
                continue
            incidents.append(_build(key, cluster, by_mac))
    incidents.sort(key=lambda i: (not i.is_open, -i.severity, _neg_ts(i.last_ts)))
    return incidents


def _split(alerts: list[Alert], window: timedelta) -> list[list[Alert]]:
    clusters: list[list[Alert]] = []
    for a in alerts:
        if clusters and _gap(clusters[-1][-1].ts, a.ts) <= window:
            clusters[-1].append(a)
        else:
            clusters.append([a])
    return clusters


def _worth_an_incident(cluster: list[Alert]) -> bool:
    if any(a.severity >= Severity.HIGH for a in cluster):
        return True
    return sum(a.severity >= Severity.MEDIUM for a in cluster) >= 2


def _build(key: str, cluster: list[Alert], by_mac: dict[str, Host]) -> Incident:
    host = by_mac.get(key)
    _, first_ip = cluster[0].entity()
    kinds = {a.kind for a in cluster}
    pattern = next((p for p in PATTERNS if p.match(kinds, cluster)), FALLBACK)
    inc = Incident(
        id=f"INC-{cluster[0].id or 0:04d}", pattern=pattern,
        mac=host.mac if host else ("" if key.startswith(("ip:", "alert:")) else key),
        ip=host.ip if host else first_ip,
        name=(host.alias or host.hostname) if host else "",
        trusted=host.trusted if host else None, alerts=cluster,
    )
    worst = max(a.severity for a in cluster)
    if len(inc.tactics) >= 3 and worst < Severity.CRITICAL:
        inc.severity, inc.escalated = Severity(worst + 10), True
    else:
        inc.severity = worst
    return inc


def find(incidents: list[Incident], incident_id: str) -> Incident | None:
    return next((i for i in incidents if i.id == incident_id.upper()), None)


def compression(alerts: list[Alert], incidents: list[Incident]) -> dict:
    """How much correlation reduces the queue: alerts an analyst would
    otherwise triage one by one versus the cases they actually open."""
    actionable = [a for a in alerts if a.status != "suppressed" and a.severity > Severity.INFO]
    in_incidents = sum(len(i.alerts) for i in incidents)
    return {"alerts": len(actionable), "incidents": len(incidents),
            "alerts_in_incidents": in_incidents,
            "ratio": round(in_incidents / len(incidents), 1) if incidents else 0.0}


# --- Helpers ----------------------------------------------------------------
def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _gap(a: str, b: str) -> timedelta:
    try:
        return _parse(b) - _parse(a)
    except ValueError:
        return timedelta(0)


def _neg_ts(ts: str) -> float:
    try:
        return -_parse(ts).timestamp()
    except ValueError:
        return 0.0


def _duration(a: str, b: str) -> str:
    secs = int(_gap(a, b).total_seconds())
    if secs < 60:
        return ""
    if secs < 3600:
        return f"{secs // 60} minutes"
    if secs < 172800:
        h = round(secs / 3600, 1)
        return f"{h:g} hours"
    return f"{secs // 86400} days"


def order_tactics(tactics: list[str]) -> list[str]:
    """Matrix order, for coverage views (incidents keep chronological order)."""
    return sorted(set(tactics), key=tactic_index)
