#!/usr/bin/env python3
"""
NetworkInventory.py

Scan a subnet for live hosts, resolve their hostnames, and export
the results to a CSV file.

Usage:
    python NetworkInventory.py 192.168.1.0/24
    python NetworkInventory.py 192.168.1.0/24 -o devices.csv --workers 100
"""

# --- Imports ----------------------------------------------------------------
import argparse
import csv
import ipaddress
import logging
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, fields
from pathlib import Path

# --- Constants --------------------------------------------------------------
DEFAULT_OUTPUT = Path("inventory.csv")
DEFAULT_WORKERS = 64
PING_TIMEOUT_MS = 500
IS_WINDOWS = platform.system() == "Windows"

logger = logging.getLogger(__name__)


# --- Classes ----------------------------------------------------------------
@dataclass
class Device:
    """A live host discovered on the network."""

    ip: str
    hostname: str = ""


# --- Functions --------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple network inventory scanner.")
    parser.add_argument("subnet", help="Subnet in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"CSV output path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Concurrent ping threads (default: {DEFAULT_WORKERS})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return parser.parse_args()


def ping(ip: str) -> bool:
    """Return True if the host answers a single ICMP echo."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), ip]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    # On Windows, "Destination host unreachable" can still return exit code 0,
    # so also require a TTL in the reply.
    return result.returncode == 0 and "ttl=" in result.stdout.lower()


def resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup; returns an empty string if it fails."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def probe(ip: str) -> Device | None:
    """Check one address and build a Device if it's alive."""
    if not ping(ip):
        return None
    device = Device(ip=ip, hostname=resolve_hostname(ip))
    logger.debug("Found %s", device)
    return device


def scan_network(subnet: str, workers: int) -> list[Device]:
    """Probe every host address in the subnet concurrently."""
    network = ipaddress.ip_network(subnet, strict=False)
    addresses = [str(ip) for ip in network.hosts()]
    logger.info("Scanning %d addresses in %s ...", len(addresses), network)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(probe, addresses)

    return [d for d in results if d is not None]


def export_csv(devices: list[Device], path: Path) -> None:
    """Write devices to a CSV file."""
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[fld.name for fld in fields(Device)])
        writer.writeheader()
        writer.writerows(asdict(d) for d in devices)
    logger.info("Wrote %d devices to %s", len(devices), path.resolve())


# --- Entry point ------------------------------------------------------------
def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    devices = scan_network(args.subnet, args.workers)
    for d in devices:
        print(f"{d.ip:<16} {d.hostname}")
    export_csv(devices, args.output)


if __name__ == "__main__":
    main()
