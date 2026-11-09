# Detection catalog

Every NetGuard detection, written up the way a detection-engineering team
documents rules: what it looks for, why it matters, where it is blind, how
to tune it, and the test that proves it fires.

Each rule is mapped to MITRE ATT&CK. Rules with a **simulation** are replayed
on every CI run by `netguard validate` (see
[`netguard/simulate.py`](../netguard/simulate.py)). Scan-based rules are
covered by unit tests in [`tests/test_detect.py`](../tests/test_detect.py).
Live per-rule statistics (volume, true-positive rate, time to resolve) are on
the dashboard's **Detections** page.

| Rule | Severity | ATT&CK | Data source | Validated by |
|---|---|---|---|---|
| [`gateway_arp_spoof`](#gateway_arp_spoof) | CRITICAL | T1557.002 | live ARP / pcap | simulation `arp_spoof_gateway` |
| [`rogue_dhcp`](#rogue_dhcp) | CRITICAL | T1557.003 | live DHCP / pcap | simulation `rogue_dhcp` |
| [`gateway_mac_changed`](#gateway_mac_changed) | CRITICAL | T1557.002 | ARP sweep | unit test |
| [`arp_spoof`](#arp_spoof) | HIGH | T1557.002 | ARP sweep | unit test |
| [`port_scan`](#port_scan) | HIGH | T1046 | live TCP / pcap | simulation `port_scan` |
| [`new_port`](#new_port) | HIGH / MEDIUM | T1021, T1133 | TCP connect check | unit test |
| [`arp_mismatch`](#arp_mismatch) | MEDIUM | T1557.002 | live ARP / pcap | simulation `arp_poison_host` |
| [`new_host`](#new_host) | MEDIUM | T1200, T1078 | ARP sweep | unit test |
| [`duplicate_mac`](#duplicate_mac) | MEDIUM | T1557.002 | ARP sweep | unit test |
| [`ip_changed_hands`](#ip_changed_hands) | LOW | (context) | ARP sweep | unit test |

Two scenarios check for **false positives** rather than detections: normal
traffic must stay silent (`benign_baseline`), and a low-and-slow scan
documents a known gap (`slow_scan_below_threshold`, see [`port_scan`](#port_scan)).

---

## Severity model

| Severity | Meaning | Expected response |
|---|---|---|
| CRITICAL | Interception of traffic is happening or has happened | Act within minutes: isolate the device |
| HIGH | Attack precursor, or new attack surface on a known device | Investigate the same day |
| MEDIUM | Change that is usually benign but must be explained | Review at the next triage pass |
| LOW | Context for investigations; normal network churn | No action on its own |

Incident correlation raises severity one level when one device's alerts span
three or more ATT&CK tactics (see [`correlate.py`](../netguard/correlate.py)),
because a multi-stage sequence is worse than any of its parts.

---

## gateway_arp_spoof

**Live ARP traffic claims the gateway's IP for a MAC other than the router's.**

- **ATT&CK:** T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning (Credential Access, Collection)
- **Logic:** every ARP packet asserts "IP *x* is at MAC *y*". If *x* is the gateway and *y* is not the
  baselined gateway MAC, alert. Five-minute cooldown per (IP, MAC) pair.
- **Why it matters:** this is the signature of arpspoof, Ettercap and Bettercap. Once a victim's cache
  is poisoned, all its off-network traffic flows through the attacker.
- **Blind spots:** on Wi-Fi the sensor only sees broadcast ARP and its own traffic, so a *unicast*
  poisoning aimed at another client may be invisible. A wired sensor on a mirrored port sees everything.
- **False positives:** router replacement or failover pairs (VRRP/HSRP, rare at home). Re-baseline after
  replacing the router.
- **Tuning:** pin the gateway MAC with `netguard baseline`; no thresholds to tune.
- **Validation:** `arp_spoof_gateway` sends 10 unsolicited replies at 2 s intervals; exactly one alert
  must fire (cooldown working) on the first poisoned frame.

## rogue_dhcp

**A DHCP OFFER or ACK came from a server that isn't the legitimate one.**

- **ATT&CK:** T1557.003 Adversary-in-the-Middle: DHCP Spoofing
- **Logic:** track the server identifier (option 54) of every OFFER/ACK. With no allow-list configured,
  the first server seen is trusted (and an INFO `dhcp_server_learned` alert records that decision).
- **Why it matters:** a rogue server can name itself as default gateway or DNS server and intercept
  traffic without any ARP tricks.
- **Blind spots:** only sees DHCP exchanges that reach the sensor (broadcast, so usually all of them on
  the same segment). `netguard dhcp-check` probes actively.
- **False positives:** travel routers, a second access point or Pi-hole with DHCP enabled.
- **Tuning:** set `[sniff] dhcp_servers = ["192.168.1.1"]` so nothing is trusted by default.
- **Validation:** `rogue_dhcp`: a phone's DISCOVER is answered by both the router and a Raspberry Pi
  offering itself as router and DNS.

## gateway_mac_changed

**The router's MAC differs from the baseline at scan time.**

- **ATT&CK:** T1557.002
- **Logic:** the periodic ARP sweep resolves the gateway IP; compare with the baselined MAC.
- **Why it matters:** the scan-time counterpart of `gateway_arp_spoof`. It needs no packet capture
  privileges, so it works on every install.
- **Blind spots:** only checks once per interval (5 min by default); an attacker who poisons briefly
  between scans is missed. Enable live capture to close the gap.
- **False positives:** router or modem replaced. Re-baseline.

## arp_spoof

**One MAC answers for the gateway's IP and another IP in the same sweep.**

- **ATT&CK:** T1557.002
- **Logic:** group sweep results by MAC; a MAC holding several IPs *including the gateway* that is not
  the baselined gateway MAC is impersonating the router.
- **False positives:** none expected; a router that owns several IPs is the baselined gateway MAC and is
  reported as `duplicate_mac` instead.

## port_scan

**One source touched 15 or more distinct TCP ports within 10 seconds.**

- **ATT&CK:** T1046 Network Service Discovery (Discovery)
- **Logic:** sliding window per source IP over initial SYNs (SYN set, ACK clear). Repeated connections
  to the same port don't count. 60 s cooldown per source.
- **Why it matters:** reconnaissance usually precedes exploitation; in an incident it marks the
  transition from "on the network" to "looking for targets".
- **Blind spots:**
  - **Low-and-slow scans.** One probe every 15 s never puts 15 ports in a 10 s window. This is a
    deliberate trade-off (a longer window flags busy servers) and is recorded as a known gap by the
    `slow_scan_below_threshold` scenario, which asserts the rule stays *silent*.
  - **Cooldown folding.** A scanner that sweeps several hosts within 60 s produces one alert. The
    incident report and `netguard pcap` still show every SYN. See the
    [case study](case-study-INC-0015.md).
  - On Wi-Fi, live capture only sees scans aimed at the sensor itself. Offline pcap analysis has no
    such restriction.
- **False positives:** authorized vulnerability scanners and network audit jobs.
- **Tuning:** suppress the scanner's IP (`Rules` page, or "Suppress similar" on the alert); adjust
  `port_scan_threshold` / `port_scan_window`.
- **Validation:** `port_scan` sends a 30-port SYN sweep in 1.5 s; `slow_scan_below_threshold` sends
  20 ports over 5 minutes and must not fire.

## new_port

**A known device started listening on a port it never had open.**

- **ATT&CK:** T1021 Remote Services, T1133 External Remote Services
- **Logic:** compare each scan's open ports (TCP connect check of 27 common ports) against the device's
  port baseline. HIGH for remote-access and backdoor ports (22, 23, 135, 139, 445, 3389, 4444, 5900,
  6379, 27017), MEDIUM otherwise. Closing ports never alert; a port only counts as closed after two
  missed checks.
- **Why it matters:** new attack surface, or a backdoor listener (4444 is Metasploit's default).
- **Blind spots:** only the 27 checked ports; UDP services are not checked.
- **False positives:** OS updates re-enabling SMB, new apps. Resolving the alert accepts the port into
  the baseline.

## arp_mismatch

**Live ARP rebinds a known IP to a new MAC.**

- **ATT&CK:** T1557.002
- **Logic:** like `gateway_arp_spoof`, for any non-gateway IP. The new binding is accepted after one
  alert, because legitimate DHCP reassignment looks identical.
- **False positives:** DHCP reassignment, phones rotating private MAC addresses.
- **Tuning:** correlate with `offline` events for the old MAC. Several mismatches in a short window
  point to poisoning, not DHCP.
- **Validation:** `arp_poison_host`: the attacker tells the router that the laptop's IP is at its MAC.
  The scenario also asserts that `gateway_arp_spoof` does **not** fire.

## new_host

**A MAC that is not in the baseline joined the network.**

- **ATT&CK:** T1200 Hardware Additions, T1078 Valid Accounts (someone with the Wi-Fi password)
- **Logic:** reported once per MAC; the device then lives in the inventory as untrusted until an analyst
  trusts it.
- **False positives:** guests, new gadgets, and phones with private Wi-Fi addresses (labelled
  "randomized MAC" so this is visible at a glance).

## duplicate_mac

**One MAC answers for several IPs (not including the gateway).**

- **ATT&CK:** T1557.002
- **False positives:** routers with a management IP, bridges, VM hosts. The demo suppresses the router's
  own duplicate with a documented rule; suppressed alerts are still stored for audit.

## ip_changed_hands

**A trusted device's IP is now held by another MAC.** LOW, context only: normal DHCP churn looks the
same. Its value is in correlation: it makes ARP-based alerts on the same IP easier to explain.

---

## Adding a detection

1. Write the rule in [`detect.py`](../netguard/detect.py) as a pure function or a `feed()` watcher.
2. Add a playbook (title, ATT&CK, triage, response) and detection metadata in
   [`playbooks.py`](../netguard/playbooks.py).
3. Add a scenario to [`simulate.py`](../netguard/simulate.py) that must make it fire, and, if the rule
   has an obvious false-positive source, one that must *not*.
4. `netguard validate` and `pytest`. CI runs both.
