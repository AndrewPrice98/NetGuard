from netguard.discovery import (
    is_randomized_mac, lookup_vendor, normalize_mac, parse_arp_output,
    parse_default_gateway,
)

WINDOWS_ARP = """
Interface: 192.168.1.50 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           a0-b1-c2-d3-e4-f5     dynamic
  192.168.1.20          b8-27-eb-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

LINUX_IP_NEIGH = """
192.168.1.1 dev eth0 lladdr a0:b1:c2:d3:e4:f5 REACHABLE
192.168.1.30 dev eth0 lladdr 3a:11:22:33:44:55 STALE
192.168.1.99 dev eth0  FAILED
192.168.1.98 dev eth0 INCOMPLETE
"""

MAC_ARP = """
? (192.168.1.1) at a0:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]
? (192.168.1.40) at 0:c:29:a:b:c on en0 ifscope [ethernet]
? (192.168.1.41) at (incomplete) on en0 ifscope [ethernet]
"""


def test_parse_windows_arp_skips_broadcast_and_multicast():
    assert parse_arp_output(WINDOWS_ARP) == {
        "192.168.1.1": "a0:b1:c2:d3:e4:f5",
        "192.168.1.20": "b8:27:eb:11:22:33",
    }


def test_parse_linux_ip_neigh_skips_failed():
    assert parse_arp_output(LINUX_IP_NEIGH) == {
        "192.168.1.1": "a0:b1:c2:d3:e4:f5",
        "192.168.1.30": "3a:11:22:33:44:55",
    }


def test_parse_macos_arp_pads_short_octets():
    assert parse_arp_output(MAC_ARP) == {
        "192.168.1.1": "a0:b1:c2:d3:e4:f5",
        "192.168.1.40": "00:0c:29:0a:0b:0c",
    }


def test_normalize_mac():
    assert normalize_mac("AA-BB-C-DD-EE-FF") == "aa:bb:0c:dd:ee:ff"


def test_vendor_and_randomized():
    assert lookup_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert is_randomized_mac("3a:11:22:33:44:55")
    assert lookup_vendor("3a:11:22:33:44:55") == "randomized MAC"
    assert lookup_vendor("a0:b1:c2:d3:e4:f5") == ""


def test_parse_default_gateway_all_platforms():
    assert parse_default_gateway("default via 10.0.0.1 dev wlan0 proto dhcp") == "10.0.0.1"
    assert parse_default_gateway("   route to: default\n    gateway: 192.168.0.1\n") == "192.168.0.1"
    windows = (
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.50     25\n"
    )
    assert parse_default_gateway(windows) == "192.168.1.1"
    assert parse_default_gateway("nothing useful here") is None
