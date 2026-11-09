"""
NetGuard — a lightweight LAN intrusion detection system.

NetGuard builds a trusted baseline of the devices on your network, then
watches for the things that signal an intruder or a man-in-the-middle:

    * rogue hosts        — a device that was never in your baseline
    * ARP spoofing       — an IP whose MAC suddenly changes (classic MITM)
    * gateway hijacking   — your router's MAC changing out from under you
    * service drift        — a known host opening a new port (e.g. SSH/RDP)
    * port scans           — someone sweeping ports against your machine

It is purely defensive: it observes your own network and reports what
changed. Nothing it does touches other networks or attacks anything.
"""

from .models import Alert, Event, Host, PortState, Severity

__all__ = ["Alert", "Event", "Host", "PortState", "Severity"]
__version__ = "0.3.0"
