"""
Core data types shared across NetGuard.

Keeping these as small dataclasses (rather than passing dicts around) makes
the detection logic readable and keeps the SQLite layer honest about its
columns.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import enum
from dataclasses import dataclass, field


# --- Severity ---------------------------------------------------------------
class Severity(enum.IntEnum):
    """Ordered so alerts can be filtered/sorted by importance."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name


# --- Host -------------------------------------------------------------------
@dataclass
class Host:
    """A device observed on the network, identified primarily by its MAC.

    MAC is the identity because an attacker can trivially change an IP but a
    spoofed MAC is both rarer and itself a signal worth alerting on.
    """

    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""
    trusted: bool = False
    device_type: str = ""
    alias: str = ""      # analyst-assigned name, e.g. "Alex's laptop"
    notes: str = ""      # analyst notes (asset owner, purpose, ...)
    online: bool = True  # answered the most recent scan

    def label(self) -> str:
        """Human-friendly identifier for alert messages."""
        bits = [self.ip or "?", self.mac]
        if self.alias:
            bits.append(f'"{self.alias}"')
        if self.hostname:
            bits.append(self.hostname)
        if self.vendor:
            bits.append(f"({self.vendor})")
        return " ".join(bits)


# --- PortState --------------------------------------------------------------
@dataclass
class PortState:
    """An open port discovered on a host."""

    mac: str
    port: int
    proto: str = "tcp"
    service: str = ""
    first_seen: str = ""
    last_seen: str = ""


# --- Alert ------------------------------------------------------------------
# Triage workflow. "Open" alerts still need an analyst.
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive", "suppressed")
OPEN_STATUSES = ("new", "investigating")

# Detail keys that name the device an alert is about, in priority order.
_MAC_KEYS = ("mac", "claimed_mac", "new_mac", "server_mac")
_IP_KEYS = ("ip", "src", "server_ip")


@dataclass
class Alert:
    """Something worth a human's attention."""

    severity: Severity
    kind: str
    message: str
    ts: str = ""
    details: dict = field(default_factory=dict)
    id: int | None = None
    status: str = "new"
    notes: str = ""
    updated_at: str = ""

    @property
    def acked(self) -> bool:
        return self.status not in OPEN_STATUSES

    def entity(self) -> tuple[str, str]:
        """(mac, ip) of the device this alert is about; blanks if unknown."""
        mac = next((self.details[k] for k in _MAC_KEYS if self.details.get(k)), "")
        ip = next((self.details[k] for k in _IP_KEYS if self.details.get(k)), "")
        return str(mac), str(ip)

    def to_dict(self) -> dict:
        mac, ip = self.entity()
        return {"id": self.id, "ts": self.ts, "severity": self.severity.name,
                "level": int(self.severity), "kind": self.kind,
                "message": self.message, "details": self.details,
                "status": self.status, "acked": self.acked, "notes": self.notes,
                "updated_at": self.updated_at, "mac": mac, "ip": ip}


# --- Event ------------------------------------------------------------------
@dataclass
class Event:
    """Something that happened on the network: not necessarily bad, but the
    raw material of an investigation (device came online, changed IP...)."""

    kind: str
    message: str
    mac: str = ""
    ip: str = ""
    ts: str = ""
    details: dict = field(default_factory=dict)
    id: int | None = None

    def to_dict(self) -> dict:
        return {"id": self.id, "ts": self.ts, "kind": self.kind, "message": self.message,
                "mac": self.mac, "ip": self.ip, "details": self.details}
