# NetGuard

A lightweight intrusion detection system for home and small-office networks,
with a live web dashboard.

NetGuard learns what your network normally looks like, then tells you when
something changes in a way that suggests an intruder or a man-in-the-middle:
a device that has never been seen before, a router whose hardware address
suddenly changes, a second DHCP server, a laptop that has started listening
for remote desktop connections.

![NetGuard dashboard showing a live ARP-spoofing alert](docs/dashboard-dark.png)

*The demo network (`netguard demo`): an attacker at 192.168.1.87 is spoofing
the router's ARP entry and has scanned the network.*

NetGuard only watches your own network. It doesn't attack anything and
doesn't scan outside the subnet it's given.

## What it detects

| Alert | Severity | What it means | How |
|---|---|---|---|
| `gateway_mac_changed` | CRITICAL | The router's MAC changed since the baseline | scan |
| `gateway_arp_spoof` | CRITICAL | Live ARP traffic claims the router's IP for another MAC | sniffer |
| `rogue_dhcp` | CRITICAL | A second DHCP server is handing out addresses | sniffer / `dhcp-check` |
| `arp_spoof` | HIGH | One MAC answers for the router's IP *and* another IP | scan |
| `port_scan` | HIGH | 15+ ports probed on this machine within 10 s | sniffer |
| `new_port` | HIGH / MEDIUM | A known device started listening on a new port. HIGH for remote-access ports (SSH, RDP, VNC, SMB, Telnet, 4444, ...) | scan |
| `new_host` | MEDIUM | A device that isn't in the baseline joined | scan |
| `duplicate_mac` | MEDIUM | One MAC is claiming several IPs | scan |
| `arp_mismatch` | MEDIUM | Live ARP rebinds a known IP to a new MAC | sniffer |
| `ip_changed_hands` | LOW | A trusted device's IP is now held by another MAC (often just DHCP) | scan |

"Scan" checks run every interval with no special privileges. "Sniffer" checks
are optional: they watch packets live and catch an attack within seconds
instead of at the next scan.

## Quick start

Requires Python 3.11+. The core uses only the standard library.

```bash
pip install -e .            # or run everything as `python -m netguard ...`

netguard demo               # try the dashboard on a fictional network first
netguard serve --open       # the real thing: baseline + monitoring + dashboard
```

The first scan of an empty database becomes the trusted baseline. After that,
anything new is flagged. Open <http://localhost:8000>.

## The dashboard: built around an analyst's workflow

| View | What it's for |
|---|---|
| **Overview** | KPIs, alerts over time by severity, top alert types, network map, "needs attention" queue, riskiest devices, recent activity |
| **Alerts** | A triage queue: New → Investigating → Resolved / False positive. Filter by status, severity, type, time and free text; bulk actions; CSV/JSON export with MITRE IDs |
| **Devices** | Asset inventory with a **risk score** per device, online/offline state, aliases and notes; CSV export |
| **Activity** | Timeline of every arrival, departure, IP change and port change: the raw material of an investigation |
| **Rules** | Suppression rules that tune out known-benign noise, with reason, hit count and last hit for auditability |

![Alert triage panel with MITRE ATT&CK mapping and playbook](docs/alert-triage.png)

Clicking any alert opens an **investigation panel**:

- the **MITRE ATT&CK** technique (e.g. T1557.002 ARP Cache Poisoning, T1046 Network Service Discovery) and tactic;
- a plain-language explanation;
- a **triage checklist** and **response steps** written for that alert type;
- timestamped **investigation notes**;
- related alerts for the same device;
- one-click **"Suppress similar…"**, which creates a rule and closes the alert as a false positive.

Clicking a device opens its **profile**:

- a risk score with the factors behind it (untrusted, open alerts, remote-access ports, …);
- port history showing open/closed state;
- analyst alias and notes;
- a merged timeline of its events and alerts.

![Device investigation panel](docs/device-investigation.png)

Suppressed alerts are still stored (visible under *Suppressed*), so tuning never
destroys evidence. Events are debounced: a device goes "offline", or a port
"closed", only after missing **two** consecutive checks, so sleepy printers and
phones in power-save don't flood the timeline.

## Command line

```bash
netguard baseline                 # (re)learn the current network as trusted
netguard scan                     # one check against the baseline
netguard watch -i 120             # check every 2 min in the terminal
netguard serve --sniff            # dashboard + live detection (admin + scapy)
netguard hosts                    # device list with type and ports
netguard alerts --min HIGH --open # open (new/investigating) high & critical alerts
netguard trust aa:bb:cc:dd:ee:ff  # also: untrust, forget
netguard report -d 30 -o month.html
netguard update-oui               # download the full IEEE vendor registry
netguard dhcp-check               # actively look for rogue DHCP servers
netguard test-notify              # check your notification setup
```

## Configuration

Copy [`netguard.example.toml`](netguard.example.toml) to `netguard.toml`.
Every setting is optional, and command-line flags override the file. The main
sections:

- `[scan]`: subnet, interval, port checks
- `[sniff]`: live detection (`enabled = true`), thresholds, allowed DHCP servers
- `[web]`: listen address, port, access token
- `[[notify]]`: as many alert destinations as you like, each with its own
  `min_severity`:
  - `desktop`: a native notification on Windows, macOS or Linux
  - `webhook`: Discord, Slack, [ntfy.sh](https://ntfy.sh) (free phone push), or plain JSON
  - `email`: SMTP with STARTTLS; the password is read from an environment
    variable, never the file

Repeated alerts are suppressed for an hour by default, so a persistent
condition doesn't spam you. Alerts can also go to a JSON-lines file
(`[alerts] log`) for a SIEM or `jq`.

When running in the background (the Windows task, systemd), use
`netguard serve --reload`: the service restarts itself when NetGuard's files
change, so it never keeps running an old version after an update.

### Live detection (optional)

```bash
pip install -e ".[sniff]"   # scapy. On Windows also install Npcap: https://npcap.com
netguard serve --sniff      # run as administrator / root
```

## How it works

1. **Discovery.** An in-process ARP sweep needs no admin rights and launches
   no child processes. On Windows, `iphlpapi!SendARP` resolves each address
   directly. Elsewhere, a one-byte UDP poke triggers ARP and the OS cache is
   read. ARP beats ping because devices that drop ICMP still have to answer ARP.
2. **Identity is the MAC, not the IP.** IPs move around on DHCP networks.
   A MAC that changes for a fixed IP, or one MAC holding several IPs, is the
   real signal.
3. **Baseline, then diff.** Each finding is reported once. Detection rules
   are pure functions over a SQLite store, so every rule is unit-tested
   without a network.
4. **Live watchers.** `ArpWatcher`, `DhcpWatcher` and `PortScanDetector` take
   `(fields, timestamp)` events. The scapy sniffer is a thin adapter that
   feeds them packets.
5. **Fingerprinting.** Each device's type (phone, printer, TV, NAS, ...) is
   guessed from hostname, vendor and open ports. The vendor comes from the
   IEEE OUI registry (`netguard update-oui`), with a built-in fallback.

```
discovery ─┐                    ┌─ console / SQLite
portscan  ─┼─► detect ─► engine ┼─ desktop · webhook · email · JSONL
sniffer   ─┘   (rules)  (Monitor)└─ web dashboard (JSON API + static SPA)
```

### Dashboard security

A security tool's own UI shouldn't be the weak spot:

- It binds to `127.0.0.1` by default and refuses other addresses unless a token is set.
- A Host-header allow-list blocks **DNS-rebinding** attacks from malicious websites.
- State-changing requests require a custom header, which cross-site forms
  can't send (**CSRF**).
- A strict **Content-Security-Policy** applies, and the UI only ever uses
  `textContent`. Hostnames come from reverse DNS, which an attacker can
  control, so they are treated as hostile and escaped everywhere, including
  the HTML report.
- Static files are served from a whitelist with no path traversal, and the
  token is compared in constant time.
- Write requests must be capped-size JSON, and CSV exports neutralize
  **formula injection**, so a hostname like `=cmd|...` can't run in Excel.

All of this is covered by end-to-end tests in [`tests/test_web.py`](tests/test_web.py).

## Running it permanently

| Platform | How |
|---|---|
| Windows | `.\deploy\install-windows-task.ps1` (add `-Sniff` from an admin shell) registers a logon task |
| Linux / Raspberry Pi | [`deploy/netguard.service`](deploy/netguard.service), a hardened systemd unit with only `CAP_NET_RAW` |
| Docker (Linux) | `docker build -t netguard . && docker run -d --network host --cap-add NET_RAW --cap-add NET_ADMIN -v netguard-data:/data netguard` |

## Project layout

```
netguard/
  models.py       Host, PortState, Alert (triage status), Event, Severity
  store.py        SQLite (WAL): baseline, alert queue, events, suppression rules, stats, migrations
  playbooks.py    MITRE ATT&CK mapping + triage/response steps per alert type
  discovery.py    process-free ARP sweep, ARP/route table parsing
  oui.py          IEEE vendor registry download + lookup
  fingerprint.py  device-type heuristics
  portscan.py     TCP connect check of common ports
  detect.py       scan rules + ArpWatcher, DhcpWatcher, PortScanDetector
  sniffer.py      optional scapy capture + active DHCP probe
  engine.py       Monitor: scan cycle, presence/port events (debounced), sniffer, loop
  notify.py       desktop / webhook / email / JSONL sinks, de-duplication
  report.py       self-contained HTML report
  config.py       TOML config
  demo.py         fictional network for demos
  web/            stdlib HTTP server + static dashboard (HTML/CSS/JS, no build step)
  cli.py          argparse commands
tests/            pytest suite: parsing, rules, watchers, triage, notifiers, web API, security
deploy/           systemd unit, Windows Task Scheduler installer
NetworkInventory.py   the original one-file scanner NetGuard grew out of
```

## Tests

```bash
pip install -e ".[dev]"
python -m pytest
```

CI runs the suite on Windows, macOS and Linux
([`.github/workflows/tests.yml`](.github/workflows/tests.yml)).

## Limitations

- Scan-based checks see changes at each interval. Turn on `--sniff` for
  real-time ARP and DHCP detection.
- Phones with private Wi-Fi addresses get a new MAC from time to time and
  show up as `new_host`. They're labelled `randomized MAC` so this is obvious.
- On Wi-Fi, a sniffer only sees broadcast traffic and its own traffic. That
  is enough for ARP spoofing and DHCP, but port scans against *other*
  devices aren't visible.
- Device types are heuristics for readability. They are never used for detection.
