from netguard.detect import ArpWatcher, DhcpWatcher
from netguard.models import Severity

GW_IP, GW_MAC = "192.168.1.1", "a0:b1:c2:d3:e4:f5"
PC_IP, PC_MAC = "192.168.1.20", "10:22:33:44:55:66"
EVIL = "de:ad:be:ef:00:01"


def watcher():
    return ArpWatcher({GW_IP: GW_MAC, PC_IP: PC_MAC}, GW_IP, GW_MAC, cooldown=60)


# --- ARP ----------------------------------------------------------------------
def test_legit_arp_is_quiet():
    w = watcher()
    assert w.feed(GW_IP, GW_MAC, 0) is None
    assert w.feed(PC_IP, PC_MAC, 1) is None


def test_gateway_spoof_is_critical_and_rate_limited():
    w = watcher()
    a = w.feed(GW_IP, EVIL, 0)
    assert a.kind == "gateway_arp_spoof" and a.severity == Severity.CRITICAL
    assert w.feed(GW_IP, EVIL, 10) is None        # within cooldown
    assert w.feed(GW_IP, EVIL, 61).kind == "gateway_arp_spoof"  # spoofing continues


def test_gateway_binding_is_never_relearned():
    w = watcher()
    w.feed(GW_IP, EVIL, 0)
    assert w.feed(GW_IP, GW_MAC, 1) is None
    assert w.feed(GW_IP, EVIL, 100) is not None


def test_host_rebinding_reported_once_then_accepted():
    w = watcher()
    a = w.feed(PC_IP, EVIL, 0)
    assert a.kind == "arp_mismatch" and a.severity == Severity.MEDIUM
    assert w.feed(PC_IP, EVIL, 1) is None


def test_unknown_ip_and_probes_ignored():
    w = watcher()
    assert w.feed("192.168.1.77", EVIL, 0) is None
    assert w.feed("0.0.0.0", EVIL, 0) is None


def test_update_swaps_bindings():
    w = ArpWatcher()
    assert w.feed(GW_IP, EVIL, 0) is None          # nothing known yet
    w.update({PC_IP: PC_MAC}, GW_IP, GW_MAC)
    assert w.feed(GW_IP, EVIL, 1).kind == "gateway_arp_spoof"


# --- DHCP ---------------------------------------------------------------------
def test_dhcp_learns_first_server():
    w = DhcpWatcher()
    a = w.feed(GW_IP, GW_MAC, "192.168.1.50", 0)
    assert a.kind == "dhcp_server_learned" and a.severity == Severity.INFO
    assert w.feed(GW_IP, GW_MAC, "192.168.1.51", 1) is None


def test_rogue_dhcp_is_critical():
    w = DhcpWatcher({GW_IP}, cooldown=60)
    a = w.feed("192.168.1.66", EVIL, "192.168.1.52", 0)
    assert a.kind == "rogue_dhcp" and a.severity == Severity.CRITICAL
    assert w.feed("192.168.1.66", EVIL, "192.168.1.53", 5) is None


def test_dhcp_without_learning_flags_everything():
    w = DhcpWatcher(learn_first=False)
    assert w.feed(GW_IP, GW_MAC, "", 0).kind == "rogue_dhcp"
