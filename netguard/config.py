"""
Configuration loaded from a TOML file (default: ./netguard.toml).

Every setting has a default, so the file is optional; command-line flags
override whatever the file says. See netguard.example.toml for all options.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity

DEFAULT_PATH = Path("netguard.toml")


# --- Sections ---------------------------------------------------------------
@dataclass
class ScanConfig:
    subnet: str = ""          # blank = the /24 around the default gateway
    interval: float = 300.0   # seconds between scans in watch/serve
    ports: bool = True
    workers: int = 128        # concurrent ARP lookups (threads, not processes)


@dataclass
class SniffConfig:
    enabled: bool = False
    iface: str = ""
    port_scan: bool = True
    arp: bool = True
    dhcp: bool = True
    port_scan_threshold: int = 15
    port_scan_window: float = 10.0
    dhcp_servers: list[str] = field(default_factory=list)  # empty = learn first seen


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    token: str = ""           # required for API calls when set


@dataclass
class AlertConfig:
    suppress_minutes: float = 60.0
    log: str = ""             # JSON-lines file path; blank = off
    log_format: str = "json"  # json | ecs (Elastic Common Schema) | cef


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    sniff: SniffConfig = field(default_factory=SniffConfig)
    web: WebConfig = field(default_factory=WebConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    notify: list[dict] = field(default_factory=list)  # raw sink tables

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        """Read `path`. A missing default file just means 'all defaults'."""
        explicit = path is not None
        path = path or DEFAULT_PATH
        if not path.exists():
            if explicit:
                raise FileNotFoundError(f"Config file not found: {path}")
            return cls()
        with path.open("rb") as f:
            return cls.from_dict(tomllib.load(f))

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        def section(klass, key):
            raw = data.get(key, {})
            known = set(klass.__dataclass_fields__)
            unknown = set(raw) - known
            if unknown:
                raise ValueError(f"Unknown setting(s) in [{key}]: {', '.join(sorted(unknown))}")
            return klass(**raw)

        notify = data.get("notify", [])
        for n in notify:
            if n.get("type") not in ("desktop", "webhook", "email", "syslog"):
                raise ValueError(f"[[notify]] type must be desktop, webhook, email or syslog: {n}")
            sev = n.get("min_severity", "HIGH").upper()
            if sev not in Severity.__members__:
                raise ValueError(f"Bad min_severity {sev!r}")

        alerts = section(AlertConfig, "alerts")
        if alerts.log_format not in ("json", "ecs", "cef"):
            raise ValueError(f"[alerts] log_format must be json, ecs or cef: {alerts.log_format!r}")
        return cls(scan=section(ScanConfig, "scan"), sniff=section(SniffConfig, "sniff"),
                   web=section(WebConfig, "web"), alerts=alerts, notify=notify)
