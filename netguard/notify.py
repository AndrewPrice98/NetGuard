"""
Alert output.

Every alert goes to the console and the SQLite history. Optional sinks,
configured under [[notify]] in netguard.toml, push it further:

    desktop  native OS notification (Windows balloon, macOS, notify-send)
    webhook  Discord, Slack, ntfy.sh or plain JSON POST
    email    SMTP (password read from an environment variable)
    syslog   RFC 5424 over UDP to a SIEM collector, CEF or ECS payload
    jsonl    log file for a SIEM / jq (via [alerts] log = "..."), JSON/ECS/CEF

Remote sinks run on a small thread pool so a slow webhook can't stall a scan.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import json
import logging
import os
import platform
import smtplib
import socket
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from . import siem
from .models import Alert, Severity
from .store import Store

logger = logging.getLogger(__name__)

# --- Constants --------------------------------------------------------------
COLORS = {
    Severity.INFO: "\033[37m",        # grey
    Severity.LOW: "\033[36m",         # cyan
    Severity.MEDIUM: "\033[33m",      # yellow
    Severity.HIGH: "\033[31m",        # red
    Severity.CRITICAL: "\033[1;41m",  # bold on red
}
RESET = "\033[0m"
NTFY_PRIORITY = {Severity.CRITICAL: "5", Severity.HIGH: "4", Severity.MEDIUM: "3",
                 Severity.LOW: "2", Severity.INFO: "1"}

if os.name == "nt":
    os.system("")  # enables ANSI escape handling in the Windows console


def is_tty() -> bool:
    """False under pythonw (no console), where sys.stdout is None."""
    return bool(sys.stdout and sys.stdout.isatty())


def format_alert(alert: Alert, color: bool = False) -> str:
    sev = f"[{alert.severity.name:<8}]"
    if color:
        sev = f"{COLORS[alert.severity]}{sev}{RESET}"
    return f"{alert.ts} {sev} {alert.kind:<20} {alert.message}"


def title_for(alert: Alert) -> str:
    return f"NetGuard {alert.severity.name}: {alert.kind.replace('_', ' ')}"


def _one_line(text: str) -> str:
    """Hostnames come from reverse DNS (attacker-controllable), so never let
    them inject newlines into headers or notification commands."""
    return " ".join(text.split())


# --- Sinks ------------------------------------------------------------------
class Sink:
    remote = False

    def __init__(self, min_severity: str = "HIGH") -> None:
        self.min_severity = Severity[min_severity.upper()]

    def wants(self, alert: Alert) -> bool:
        return alert.severity >= self.min_severity

    def send(self, alert: Alert) -> None:
        raise NotImplementedError


class JsonlSink(Sink):
    """One alert per line: NetGuard JSON, ECS JSON, or CEF (see siem.py)."""

    def __init__(self, path: Path, fmt: str = "json") -> None:
        super().__init__("INFO")
        if fmt not in siem.FORMATS:
            raise ValueError(f"Unknown log format {fmt!r}")
        self.path, self.fmt = path, fmt
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> None:
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(siem.format_alert(alert, self.fmt) + "\n")


class SyslogSink(Sink):
    """RFC 5424 syslog over UDP to a SIEM collector, CEF or ECS payload."""

    remote = True
    PRI = {Severity.CRITICAL: 2, Severity.HIGH: 3, Severity.MEDIUM: 4,
           Severity.LOW: 5, Severity.INFO: 6}  # syslog severities, facility local4

    def __init__(self, host: str, port: int = 514, format: str = "cef",
                 min_severity: str = "LOW") -> None:
        super().__init__(min_severity)
        if format not in siem.FORMATS:
            raise ValueError(f"Unknown syslog format {format!r}")
        self.host, self.port, self.format = host, int(port), format

    def build(self, alert: Alert) -> bytes:
        pri = 20 * 8 + self.PRI[alert.severity]
        host = _one_line(platform.node() or "-").replace(" ", "")[:255] or "-"
        body = _one_line(siem.format_alert(alert, self.format))
        return f"<{pri}>1 {alert.ts or '-'} {host} netguard - {alert.kind} - {body}".encode()

    def send(self, alert: Alert) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(self.build(alert)[:8192], (self.host, self.port))


class DesktopSink(Sink):
    remote = True

    WINDOWS_PS = (
        "Add-Type -AssemblyName System.Windows.Forms, System.Drawing;"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::Warning;"
        "$n.BalloonTipTitle = $env:NG_TITLE; $n.BalloonTipText = $env:NG_BODY;"
        "$n.Visible = $true; $n.ShowBalloonTip(10000); Start-Sleep -Seconds 8; $n.Dispose()"
    )

    def send(self, alert: Alert) -> None:
        title, body = _one_line(title_for(alert)), _one_line(alert.message)[:250]
        # Text travels via environment variables, never spliced into a script.
        env = {**os.environ, "NG_TITLE": title, "NG_BODY": body}
        system = platform.system()
        if system == "Windows":
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", self.WINDOWS_PS]
            flags = subprocess.CREATE_NO_WINDOW
        elif system == "Darwin":
            cmd = ["osascript", "-e", 'display notification (system attribute "NG_BODY") '
                                      'with title (system attribute "NG_TITLE")']
            flags = 0
        else:
            cmd = ["notify-send", "-u", "critical" if alert.severity >= Severity.HIGH
                   else "normal", title, body]
            flags = 0
        subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=flags)


def build_webhook_request(fmt: str, url: str, alert: Alert) -> urllib.request.Request:
    """Shape the payload each service expects. Pure, so it's unit-tested."""
    text = f"**{title_for(alert)}**\n{alert.message}"
    headers = {"User-Agent": "netguard"}
    if fmt == "discord":
        body = json.dumps({"username": "NetGuard", "content": text[:1900]}).encode()
        headers["Content-Type"] = "application/json"
    elif fmt == "slack":
        body = json.dumps({"text": text.replace("**", "*")}).encode()
        headers["Content-Type"] = "application/json"
    elif fmt == "ntfy":
        body = _one_line(alert.message).encode()
        headers.update({"Title": _one_line(title_for(alert)),
                        "Priority": NTFY_PRIORITY[alert.severity],
                        "Tags": "rotating_light" if alert.severity >= Severity.HIGH else "warning"})
    elif fmt == "json":
        body = json.dumps(alert.to_dict()).encode()
        headers["Content-Type"] = "application/json"
    else:
        raise ValueError(f"Unknown webhook format {fmt!r}")
    return urllib.request.Request(url, data=body, headers=headers, method="POST")


class WebhookSink(Sink):
    remote = True

    def __init__(self, url: str, format: str = "json", min_severity: str = "HIGH") -> None:
        super().__init__(min_severity)
        self.url, self.format = url, format
        build_webhook_request(format, url, Alert(Severity.INFO, "x", "x"))  # validate early

    def send(self, alert: Alert) -> None:
        with urllib.request.urlopen(build_webhook_request(self.format, self.url, alert),
                                    timeout=10):
            pass


class EmailSink(Sink):
    remote = True

    def __init__(self, host: str, to: list[str] | str, port: int = 587,
                 username: str = "", password_env: str = "NETGUARD_SMTP_PASSWORD",
                 starttls: bool = True, min_severity: str = "HIGH", **kw) -> None:
        super().__init__(min_severity)
        self.host, self.port, self.starttls = host, port, starttls
        self.username, self.password_env = username, password_env
        self.to = [to] if isinstance(to, str) else list(to)
        self.sender = kw.get("from") or username or "netguard@localhost"

    def build(self, alert: Alert) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = _one_line(f"[NetGuard] {alert.severity.name}: {alert.message}")[:150]
        msg["From"], msg["To"] = self.sender, ", ".join(self.to)
        msg.set_content(f"{alert.message}\n\nKind: {alert.kind}\nTime: {alert.ts}\n\n"
                        f"Details:\n{json.dumps(alert.details, indent=2)}\n")
        return msg

    def send(self, alert: Alert) -> None:
        with smtplib.SMTP(self.host, self.port, timeout=20) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.username:
                password = os.environ.get(self.password_env, "")
                if not password:
                    raise RuntimeError(f"Set the {self.password_env} environment variable")
                smtp.login(self.username, password)
            smtp.send_message(self.build(alert))


def build_sinks(notify: list[dict], jsonl: str | Path | None = None,
                jsonl_format: str = "json") -> list[Sink]:
    sinks: list[Sink] = []
    if jsonl:
        sinks.append(JsonlSink(Path(jsonl), jsonl_format))
    for raw in notify:
        opts = {k: v for k, v in raw.items() if k != "type"}
        kind = raw["type"]
        if kind == "desktop":
            sinks.append(DesktopSink(opts.get("min_severity", "HIGH")))
        elif kind == "webhook":
            sinks.append(WebhookSink(**opts))
        elif kind == "email":
            sinks.append(EmailSink(**opts))
        elif kind == "syslog":
            sinks.append(SyslogSink(**opts))
    return sinks


# --- Notifier ---------------------------------------------------------------
class Notifier:
    """Fan an alert out to every sink, suppressing recent duplicates.

    Conditions like a spoofed gateway persist across scans; without the
    suppression window the same alert would fire every interval.
    """

    _pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="netguard-notify")

    def __init__(self, store: Store, sinks: list[Sink] | None = None,
                 suppress_minutes: float = 60.0, color: bool | None = None,
                 quiet: bool = False) -> None:
        self.store = store
        self.sinks = sinks or []
        self.suppress = timedelta(minutes=suppress_minutes)
        self.color = is_tty() if color is None else color
        self.quiet = quiet
        self._recent: dict[tuple[str, str], datetime] = {}

    def emit(self, alert: Alert) -> bool:
        """Record, print and dispatch an alert. False if it was suppressed."""
        key = (alert.kind, alert.message)
        now = datetime.now(timezone.utc)
        last = self._recent.get(key)
        if last and now - last < self.suppress:
            return False
        self._recent[key] = now

        # Tuned-out noise is still recorded (auditable, and visible in the
        # "Suppressed" queue) but never printed or pushed anywhere.
        if self.store.match_suppression(alert) is not None:
            alert.status = "suppressed"
            self.store.add_alert(alert)
            return False

        self.store.add_alert(alert)  # fills in ts and id
        if not self.quiet:
            print(format_alert(alert, self.color), flush=True)
        for sink in self.sinks:
            if sink.wants(alert):
                if sink.remote:
                    self._pool.submit(_safe_send, sink, alert)
                else:
                    _safe_send(sink, alert)
        return True


def _safe_send(sink: Sink, alert: Alert) -> None:
    try:
        sink.send(alert)
    except Exception as exc:  # a broken sink must never break detection
        logger.warning("%s failed: %s", type(sink).__name__, exc)
