"""
MAC vendor lookup.

Uses the full IEEE OUI registry when it has been downloaded with
`netguard update-oui`, and falls back to a small built-in table otherwise.
The registry is ~35k entries, so it's parsed once and cached in memory.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import logging
import re
import urllib.request
from functools import lru_cache
from pathlib import Path

# --- Constants --------------------------------------------------------------
IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
DATA_DIR = Path.home() / ".netguard"
OUI_FILE = DATA_DIR / "oui.txt"

# "F8-79-0A   (hex)		Vendor Name"
LINE_RE = re.compile(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")

# A sample of well-known OUIs so vendors still show without the download.
BUILTIN = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:15:5d": "Microsoft (Hyper-V)", "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue", "18:b4:30": "Nest", "f0:9f:c2": "Ubiquiti",
    "24:a4:3c": "Ubiquiti", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "00:11:32": "Synology", "50:c7:bf": "TP-Link", "00:14:bf": "Linksys",
    "00:09:5b": "Netgear", "c0:56:27": "Belkin", "fc:65:de": "Amazon",
    "44:65:0d": "Amazon", "00:1d:d8": "Microsoft", "7c:ed:8d": "Microsoft",
    "64:16:66": "Nest", "ec:fa:bc": "Espressif", "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif", "00:26:ab": "Seiko Epson", "64:eb:8c": "Seiko Epson",
    "3c:2a:f4": "Brother", "00:80:77": "Brother", "70:5a:0f": "HP",
    "00:1e:0b": "HP", "f8:b4:6a": "HP", "cc:2d:e0": "Routerboard (MikroTik)",
    "b0:be:76": "TP-Link", "8c:85:90": "Apple", "98:da:c4": "TP-Link",
}

logger = logging.getLogger(__name__)


# --- Parsing ----------------------------------------------------------------
def parse_oui_text(text: str) -> dict[str, str]:
    """IEEE oui.txt -> {'f8:79:0a': 'Vendor Name'}."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        if m := LINE_RE.match(line):
            prefix = ":".join(m.group(i) for i in (1, 2, 3)).lower()
            table[prefix] = m.group(4)
    return table


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table = dict(BUILTIN)
    path = OUI_FILE  # read at call time so tests can point it elsewhere
    if path.exists():
        try:
            table.update(parse_oui_text(path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            logger.warning("Could not read %s: %s", path, exc)
    return table


def lookup(mac: str) -> str:
    return _table().get(mac[:8].lower(), "")


def registry_size() -> int:
    return len(_table())


# --- Updating ---------------------------------------------------------------
def update(source: Path | None = None) -> int:
    """Install the IEEE registry from the web, or from a local file.

    Returns the number of vendors parsed. A local `source` is handy behind
    TLS-intercepting proxies: download oui.txt in a browser and import it.
    """
    if source:
        text = source.read_text(encoding="utf-8", errors="replace")
    else:
        req = urllib.request.Request(IEEE_URL, headers={"User-Agent": "Mozilla/5.0 netguard"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode("utf-8", errors="replace")

    entries = parse_oui_text(text)
    if len(entries) < 1000:
        raise ValueError(f"Only {len(entries)} vendors parsed; that doesn't look like oui.txt")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUI_FILE.write_text(text, encoding="utf-8")
    _table.cache_clear()
    return len(entries)
