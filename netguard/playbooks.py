"""
Analyst playbooks: what each alert means and what to do about it.

Each alert kind maps to MITRE ATT&CK technique(s), a plain-language
explanation, triage questions (is it real?) and response steps (what to do
if it is). The dashboard shows these beside every alert, so a responder
doesn't have to remember the procedure under pressure.
"""

from __future__ import annotations

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _t(tid: str, name: str) -> dict:
    return {"id": tid, "name": name, "url": ATTACK_URL.format(tid.replace(".", "/"))}


PLAYBOOKS: dict[str, dict] = {
    "gateway_mac_changed": {
        "title": "Gateway MAC address changed",
        "tactic": "Credential Access / Collection",
        "mitre": [_t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
        "summary": "Your router's IP now resolves to a different hardware address than "
                   "in the baseline. Either the router was replaced, or a device is "
                   "impersonating it to intercept all traffic.",
        "triage": [
            "Was the router, modem or mesh base replaced or reset recently?",
            "Look up the new MAC's vendor. Does it match your router's brand?",
            "Does the new MAC also appear as another device in the inventory?",
            "Check the router's admin page: does its LAN MAC match the new one?",
        ],
        "response": [
            "If unexplained: disconnect the device that owns the new MAC.",
            "Clear ARP caches (Windows: `arp -d *`) and re-check the gateway MAC.",
            "Change Wi-Fi and router admin passwords; review connected clients.",
            "If the change is legitimate, re-baseline: `netguard baseline`.",
        ],
    },
    "gateway_arp_spoof": {
        "title": "Live ARP spoofing of the gateway",
        "tactic": "Credential Access / Collection",
        "mitre": [_t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
        "summary": "ARP packets on the wire claim the gateway's IP belongs to another "
                   "MAC. This is the signature of arpspoof/Ettercap/Bettercap-style "
                   "man-in-the-middle tools. Treat it as an active attack.",
        "triage": [
            "Identify the claimed MAC in the device list. Who owns it?",
            "Is it still happening? Watch for repeat alerts after the cooldown.",
            "Is anything on the network doing failover or VRRP? (rare at home)",
        ],
        "response": [
            "Physically locate and disconnect the offending device (switch port / Wi-Fi client).",
            "Block its MAC on the router; rotate the Wi-Fi password.",
            "Assume traffic was intercepted: change passwords used during the window.",
            "Consider static ARP for the gateway on critical machines.",
        ],
    },
    "arp_spoof": {
        "title": "Device impersonating the gateway",
        "tactic": "Credential Access / Collection",
        "mitre": [_t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
        "summary": "One MAC answers for the gateway's IP and its own. A poisoned ARP "
                   "cache that routes traffic through another machine.",
        "triage": [
            "Which device owns the MAC? Is it trusted?",
            "Does a live `gateway_arp_spoof` alert corroborate it?",
        ],
        "response": [
            "Isolate the device; block its MAC at the router.",
            "Flush ARP caches on clients; rotate credentials used since the alert.",
        ],
    },
    "arp_mismatch": {
        "title": "ARP binding changed",
        "tactic": "Credential Access",
        "mitre": [_t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
        "summary": "A known IP is now announced by a different MAC. Often a DHCP "
                   "reassignment, occasionally targeted ARP poisoning of a single host.",
        "triage": [
            "Did the original device leave the network (offline event)?",
            "Is the new MAC a known, trusted device?",
            "Several mismatches in a short window point to poisoning, not DHCP.",
        ],
        "response": [
            "If the new MAC is unknown, investigate it as a rogue device.",
            "Otherwise mark as resolved. The next scan updates the binding.",
        ],
    },
    "duplicate_mac": {
        "title": "One MAC claims several IPs",
        "tactic": "Defense Evasion",
        "mitre": [_t("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
        "summary": "A single hardware address answers for multiple IPs. Can be a "
                   "router/bridge with several addresses, a VM host, or ARP poisoning.",
        "triage": [
            "Is this device a router, access point, or VM host? Those do this legitimately.",
            "Are the extra IPs ones that other trusted devices used to hold?",
        ],
        "response": [
            "If legitimate, add a suppression rule for this device.",
            "If not, treat as ARP poisoning: isolate the device.",
        ],
    },
    "rogue_dhcp": {
        "title": "Rogue DHCP server",
        "tactic": "Credential Access / Collection",
        "mitre": [_t("T1557.003", "Adversary-in-the-Middle: DHCP Spoofing")],
        "summary": "A DHCP server other than the legitimate one is offering leases. "
                   "It can hand out itself as gateway or DNS server and silently "
                   "intercept or redirect clients' traffic.",
        "triage": [
            "Is a second router, travel router, or Pi-hole with DHCP enabled plugged in?",
            "Check the offer's router and DNS fields (`netguard dhcp-check`).",
        ],
        "response": [
            "Unplug or disable DHCP on the rogue server.",
            "Renew leases on clients (`ipconfig /renew`) and verify gateway/DNS.",
            "If malicious: identify the device, block it, and review DNS logs.",
        ],
    },
    "port_scan": {
        "title": "Port scan detected",
        "tactic": "Discovery",
        "mitre": [_t("T1046", "Network Service Discovery")],
        "summary": "One source probed many ports in a short window. This is "
                   "reconnaissance, usually the step before exploitation.",
        "triage": [
            "Is the source a trusted device? Is someone running nmap or a vulnerability scanner?",
            "Is the source external or internal? Check whether it's in the inventory.",
            "Did any `new_port` or `new_host` alerts follow?",
        ],
        "response": [
            "If unexpected: isolate the source and review what it can reach.",
            "Confirm exposed services on the target are patched and needed.",
            "Authorized scanners: add a suppression rule for that source.",
        ],
    },
    "new_port": {
        "title": "New listening service",
        "tactic": "Persistence / Lateral Movement",
        "mitre": [_t("T1021", "Remote Services"), _t("T1133", "External Remote Services")],
        "summary": "A known device started listening on a port it never had open. "
                   "Remote-access ports (SSH, RDP, VNC, SMB, 4444) can indicate a "
                   "backdoor or a newly exposed attack surface.",
        "triage": [
            "Was software installed or a setting changed on that device?",
            "Is the service expected for this kind of device (RDP on a printer is not)?",
            "Port 4444 or other unusual high ports: check running processes on the host.",
        ],
        "response": [
            "Disable the service if not needed; firewall it otherwise.",
            "For unexplained remote-access ports: treat the device as compromised.",
            "If expected, mark resolved; it is now part of that device's baseline.",
        ],
    },
    "new_host": {
        "title": "Unknown device joined",
        "tactic": "Initial Access",
        "mitre": [_t("T1200", "Hardware Additions"), _t("T1078", "Valid Accounts")],
        "summary": "A device that isn't in the baseline is on the network. Usually a "
                   "guest, a new gadget, or a phone rotating its private MAC; "
                   "occasionally an intruder with the Wi-Fi password.",
        "triage": [
            "Recognize the vendor/hostname? Did anyone add a device recently?",
            "\"Randomized MAC\": likely a phone or laptop with Wi-Fi privacy on.",
            "Does it have open ports, or did a `port_scan` come from it?",
        ],
        "response": [
            "Known device: Trust it and give it an alias.",
            "Unknown: block it at the router and rotate the Wi-Fi password.",
            "Consider a separate guest network for visitors and IoT.",
        ],
    },
    "ip_changed_hands": {
        "title": "IP reassigned",
        "tactic": "",
        "mitre": [],
        "summary": "A trusted device's address is now used by another MAC. Usually "
                   "normal DHCP churn. Kept as low severity context for investigations.",
        "triage": ["Correlate with ARP alerts around the same time."],
        "response": ["Normally no action. Resolve or add a suppression rule."],
    },
    "dhcp_server_learned": {
        "title": "DHCP server learned",
        "tactic": "",
        "mitre": [],
        "summary": "NetGuard trusted the first DHCP server it saw. Confirm it's your router.",
        "triage": ["Is the server IP your router's?"],
        "response": ["If not, set `dhcp_servers` in netguard.toml and investigate."],
    },
}

DEFAULT = {"title": "", "tactic": "", "mitre": [], "summary": "", "triage": [], "response": []}


def playbook(kind: str) -> dict:
    return {**DEFAULT, "title": kind.replace("_", " ").capitalize(), **PLAYBOOKS.get(kind, {}),
            **DETECTIONS.get(kind, {})}


# --- Detection engineering metadata ------------------------------------------
# ATT&CK enterprise tactics in matrix order. Used to order and count the
# stages of an incident, and to lay out the coverage matrix.
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# Per rule: the one tactic it represents in an attack chain ("stage"), where
# its data comes from, its default severity, and the simulated scenario
# (see simulate.py) that proves it fires. `netguard validate` runs them all.
DETECTIONS: dict[str, dict] = {
    "gateway_mac_changed": {"stage": "Credential Access", "source": "scan",
                            "default_severity": "CRITICAL",
                            "validated_by": "test_detect.py::test_arp_spoof_of_gateway"},
    "gateway_arp_spoof": {"stage": "Credential Access", "source": "sniffer / pcap",
                          "default_severity": "CRITICAL", "validated_by": "arp_spoof_gateway"},
    "arp_spoof": {"stage": "Credential Access", "source": "scan",
                  "default_severity": "HIGH", "validated_by": "test_detect.py::test_arp_spoof_of_gateway"},
    "arp_mismatch": {"stage": "Credential Access", "source": "sniffer / pcap",
                     "default_severity": "MEDIUM", "validated_by": "arp_poison_host"},
    "duplicate_mac": {"stage": "Defense Evasion", "source": "scan",
                      "default_severity": "MEDIUM",
                      "validated_by": "test_detect.py::test_duplicate_mac_without_gateway_is_medium"},
    "rogue_dhcp": {"stage": "Credential Access", "source": "sniffer / pcap",
                   "default_severity": "CRITICAL", "validated_by": "rogue_dhcp"},
    "port_scan": {"stage": "Discovery", "source": "sniffer / pcap",
                  "default_severity": "HIGH", "validated_by": "port_scan"},
    "new_port": {"stage": "Persistence", "source": "scan",
                 "default_severity": "HIGH / MEDIUM", "validated_by": "test_detect.py::test_new_risky_port_is_high"},
    "new_host": {"stage": "Initial Access", "source": "scan",
                 "default_severity": "MEDIUM", "validated_by": "test_detect.py::test_new_host_reported_once"},
    "ip_changed_hands": {"stage": "", "source": "scan",
                         "default_severity": "LOW", "validated_by": "test_detect.py::test_ip_changed_hands"},
    "dhcp_server_learned": {"stage": "", "source": "sniffer / pcap",
                            "default_severity": "INFO", "validated_by": "benign_baseline"},
}


def tactic_index(tactic: str) -> int:
    return TACTICS.index(tactic) if tactic in TACTICS else len(TACTICS)
