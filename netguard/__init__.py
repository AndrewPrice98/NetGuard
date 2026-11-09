"""
NetGuard: a lightweight network intrusion detection system and SOC console
for home and small-office networks.

Detection
    Builds a trusted baseline of the devices on the LAN, then flags rogue
    hosts, ARP spoofing, gateway hijacking, rogue DHCP servers, new listening
    services and port scans, each mapped to MITRE ATT&CK.

Response
    Correlates alerts into incidents with an attack-chain narrative, tracks
    triage with an audit trail (MTTA/MTTR), measures each rule's
    true-positive rate, and drafts incident reports.

Validation and forensics
    Replays attack simulations through the detectors (`netguard validate`)
    and runs the same detectors over packet captures (`netguard pcap`).

It is purely defensive: it observes your own network and reports what
changed. Nothing it does touches other networks or attacks anything.
"""

from .models import Alert, Event, Host, PortState, Severity

__all__ = ["Alert", "Event", "Host", "PortState", "Severity"]
__version__ = "0.4.0"
