import pytest

from netguard.detect import PortScanDetector, check_hosts, check_ports
from netguard.models import Host, PortState, Severity
from netguard.store import Store

GW_IP, GW_MAC = "192.168.1.1", "a0:b1:c2:d3:e4:f5"
PC_IP, PC_MAC = "192.168.1.20", "10:22:33:44:55:66"
EVIL_MAC = "de:ad:be:ef:00:01"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def hosts(*pairs):
    return [Host(mac=mac, ip=ip) for ip, mac in pairs]


def kinds(alerts):
    return sorted(a.kind for a in alerts)


@pytest.fixture
def baselined(store):
    check_hosts(store, hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC)), GW_IP, learn=True)
    return store


# --- Hosts ------------------------------------------------------------------
def test_baseline_raises_nothing_and_trusts_everyone(store):
    alerts = check_hosts(store, hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC)), GW_IP, learn=True)
    assert alerts == []
    assert all(h.trusted for h in store.all_hosts())
    assert store.get_meta("gateway_mac") == GW_MAC


def test_unchanged_network_is_quiet(baselined):
    assert check_hosts(baselined, hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC)), GW_IP) == []


def test_new_host_reported_once(baselined):
    seen = hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC), ("192.168.1.66", EVIL_MAC))
    first = check_hosts(baselined, seen, GW_IP)
    assert kinds(first) == ["new_host"]
    assert first[0].severity == Severity.MEDIUM
    assert not baselined.get_host(EVIL_MAC).trusted

    seen = hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC), ("192.168.1.66", EVIL_MAC))
    assert check_hosts(baselined, seen, GW_IP) == []


def test_arp_spoof_of_gateway(baselined):
    # Classic arpspoof: the attacker's MAC answers for the gateway IP *and*
    # its own IP, so the gateway's MAC changes and is duplicated.
    seen = hosts((GW_IP, EVIL_MAC), (PC_IP, PC_MAC), ("192.168.1.66", EVIL_MAC))
    alerts = check_hosts(baselined, seen, GW_IP)
    assert kinds(alerts) == ["arp_spoof", "gateway_mac_changed", "new_host"]
    by_kind = {a.kind: a for a in alerts}
    assert by_kind["gateway_mac_changed"].severity == Severity.CRITICAL
    assert by_kind["arp_spoof"].severity == Severity.HIGH
    # The baseline gateway MAC must not be overwritten by the attacker.
    assert baselined.get_meta("gateway_mac") == GW_MAC


def test_duplicate_mac_without_gateway_is_medium(baselined):
    seen = hosts((GW_IP, GW_MAC), (PC_IP, PC_MAC), ("192.168.1.21", PC_MAC))
    alerts = check_hosts(baselined, seen, GW_IP)
    assert kinds(alerts) == ["duplicate_mac"]
    assert alerts[0].severity == Severity.MEDIUM


def test_ip_changed_hands(baselined):
    seen = hosts((GW_IP, GW_MAC), (PC_IP, EVIL_MAC))
    alerts = check_hosts(baselined, seen, GW_IP)
    assert kinds(alerts) == ["ip_changed_hands", "new_host"]


def test_gateway_trust_on_first_use(store):
    check_hosts(store, hosts((GW_IP, GW_MAC)), GW_IP)
    assert store.get_meta("gateway_mac") == GW_MAC


# --- Ports ------------------------------------------------------------------
def test_first_port_scan_is_silent_baseline(baselined):
    pc = baselined.get_host(PC_MAC)
    assert check_ports(baselined, pc, [PortState(PC_MAC, 80, service="http")]) == []


def test_new_risky_port_is_high(baselined):
    pc = baselined.get_host(PC_MAC)
    check_ports(baselined, pc, [PortState(PC_MAC, 80)], learn=True)
    alerts = check_ports(baselined, pc,
                         [PortState(PC_MAC, 80), PortState(PC_MAC, 3389, service="rdp")])
    assert kinds(alerts) == ["new_port"]
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].details["port"] == 3389


def test_new_ordinary_port_is_medium_and_closed_port_ignored(baselined):
    pc = baselined.get_host(PC_MAC)
    check_ports(baselined, pc, [PortState(PC_MAC, 80)], learn=True)
    alerts = check_ports(baselined, pc, [PortState(PC_MAC, 8080)])
    assert [a.severity for a in alerts] == [Severity.MEDIUM]
    # ...and the next identical scan is quiet.
    assert check_ports(baselined, pc, [PortState(PC_MAC, 8080)]) == []


# --- Port-scan detector -----------------------------------------------------
def test_port_scan_detected_at_threshold():
    d = PortScanDetector(threshold=5, window=10, cooldown=60)
    results = [d.feed("10.0.0.9", port, ts=float(i)) for i, port in enumerate(range(1, 6))]
    assert results[:4] == [None] * 4
    assert results[4].kind == "port_scan"


def test_repeated_hits_on_one_port_are_not_a_scan():
    d = PortScanDetector(threshold=5)
    assert all(d.feed("10.0.0.9", 443, ts=i * 0.1) is None for i in range(100))


def test_slow_scan_outside_window_is_ignored():
    d = PortScanDetector(threshold=5, window=10)
    assert all(d.feed("10.0.0.9", p, ts=p * 20.0) is None for p in range(1, 20))


def test_cooldown_suppresses_repeat_alerts():
    d = PortScanDetector(threshold=3, window=10, cooldown=60)
    alerts = [d.feed("10.0.0.9", p, ts=p * 0.1) for p in range(1, 30)]
    assert sum(a is not None for a in alerts) == 1
