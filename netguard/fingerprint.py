"""
Best-guess device classification from passive clues.

Combines three cheap signals NetGuard already has: hostname, MAC vendor and
open ports. It's a heuristic for making the device list readable, never an
input to detection, so a wrong guess costs nothing.
"""

# --- Imports ----------------------------------------------------------------
from __future__ import annotations

import re

from .models import Host

# --- Rules ------------------------------------------------------------------
# Checked in order; first match wins. (type, hostname/vendor regex)
NAME_RULES: list[tuple[str, str]] = [
    ("phone", r"iphone|android|galaxy|pixel|oneplus|xiaomi|redmi|motorola|huawei-p|sm-[gans]\d"),
    ("tablet", r"ipad|tab-?s\d|kindle|fire-?hd"),
    ("console", r"xbox|playstation|ps[45]|nintendo|switch-"),
    ("printer", r"epson|canon|brother|printer|laserjet|officejet|deskjet|hp[0-9a-f]{6}|kyocera|lexmark|xerox"),
    ("tv", r"\btv\b|-tv|roku|chromecast|fire-?tv|bravia|webos|tizen|vizio|appletv|apple-tv|shield"),
    ("speaker", r"echo|alexa|google-?home|nest-?(mini|audio|hub)|sonos|homepod"),
    ("camera", r"cam\b|camera|ipcam|ring-|arlo|wyze|reolink|hikvision|dahua|blink"),
    ("nas", r"synology|qnap|diskstation|\bnas\b|truenas|unraid"),
    ("iot", r"esp[-_]?\w*|tasmota|shelly|tuya|hue|smartthings|ecobee|nest|meross|kasa|wemo|espressif"),
    ("network", r"ubiquiti|unifi|mikrotik|routerboard|netgear|tp-?link|linksys|eero|orbi|asus-?rt|access.?point|\bap\b"),
    ("computer", r"desktop|laptop|-pc\b|^pc-|macbook|imac|mac-?mini|thinkpad|surface|workstation"),
    ("sbc", r"raspberry|raspberrypi|\bpi\b|odroid|jetson"),
    ("vm", r"vmware|virtualbox|hyper-v|qemu|proxmox"),
]

# Open port -> type, for devices whose name/vendor told us nothing.
PORT_RULES: list[tuple[str, set[int]]] = [
    ("printer", {9100, 631, 515}),
    ("camera", {554}),
    ("nas", {548, 5000, 5001}),
    ("computer", {3389, 135, 139, 445}),
    ("iot", {1883}),
    ("server", {22, 3306, 5432, 6379, 27017, 8000, 8080}),
]

TYPE_LABELS = {
    "router": "Router", "phone": "Phone", "tablet": "Tablet", "console": "Game console",
    "printer": "Printer", "tv": "TV / streamer", "speaker": "Smart speaker",
    "camera": "Camera", "nas": "NAS", "iot": "Smart-home / IoT",
    "network": "Network gear", "computer": "Computer", "sbc": "Single-board computer",
    "vm": "Virtual machine", "server": "Server", "mobile": "Phone / tablet",
    "unknown": "Unknown",
}


# --- Classification ---------------------------------------------------------
def classify(host: Host, ports: set[int] | None = None,
             gateway_ip: str | None = None) -> str:
    """Return a type key from TYPE_LABELS."""
    if gateway_ip and host.ip == gateway_ip:
        return "router"

    text = f"{host.hostname} {host.vendor}".lower()
    for dtype, pattern in NAME_RULES:
        if re.search(pattern, text):
            return dtype

    for dtype, wanted in PORT_RULES:
        if ports and ports & wanted:
            return dtype

    # Private (randomized) MACs are almost always phones/tablets/laptops
    # using Wi-Fi privacy features.
    if host.vendor == "randomized MAC":
        return "mobile"
    if "apple" in text:
        return "computer" if ports else "mobile"
    return "unknown"
