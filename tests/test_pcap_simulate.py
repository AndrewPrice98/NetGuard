"""Offline capture analysis and attack-simulation validation."""

import struct

import pytest

from netguard import pcap, simulate
from netguard.simulate import (ATTACKER, GW, LAPTOP, SCENARIOS, arp, ether, write_pcap)


# --- Detection validation: every scenario, as a regression test ---------------
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_scenario_meets_expectations(scenario):
    result = simulate.validate(scenario)
    assert not result.missing, f"{scenario.name}: expected {result.missing} to fire"
    assert not result.unexpected, f"{scenario.name}: unexpected {result.unexpected}"


def test_alerts_carry_packet_evidence():
    r = simulate.validate(simulate.scenario("mitm_kill_chain"))
    spoof = next(a for a in r.analysis.alerts if a.kind == "gateway_arp_spoof")
    assert spoof.details["frame"] > 0 and spoof.details["evidence"] == "mitm_kill_chain.pcap"
    assert spoof.ts.startswith("2026-01-15T14:03")  # packet time, not wall-clock time
    assert spoof.details["claimed_mac"] == ATTACKER[1]


def test_gateway_learned_from_dhcp():
    a = simulate.run(simulate.scenario("benign_baseline"))
    assert (a.gateway_ip, a.gateway_mac, a.gateway_source) == (GW[0], GW[1], "DHCP router option")
    assert a.dhcp_servers[0]["router"] == GW[0]
    assert {LAPTOP[1], GW[1]} <= set(a.hosts)


# --- File formats -------------------------------------------------------------
def test_pcap_round_trip(tmp_path):
    s = simulate.scenario("port_scan")
    path = tmp_path / "scan.pcap"
    write_pcap(path, s.build())
    result = pcap.analyze(path)
    assert result.packets == len(s.build())
    assert [a.kind for a in result.alerts if a.kind == "port_scan"] == ["port_scan"]
    assert result.protocols["tcp_syn"] >= 15


def _pcapng(frames, linktype=1, tsresol=6):
    def block(btype, body):
        body += b"\0" * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535) + opts)
    out = shb + idb
    for ts, data in frames:
        ticks = int(ts * 10 ** tsresol)
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                    len(data), len(data)) + data)
    return out


def test_pcapng_and_timestamp_resolution():
    spoof = ether(LAPTOP[1], ATTACKER[1], 0x0806, arp(2, ATTACKER[1], GW[0], LAPTOP[1], LAPTOP[0]))
    legit = ether(LAPTOP[1], GW[1], 0x0806, arp(2, GW[1], GW[0], LAPTOP[1], LAPTOP[0]))
    for res in (6, 9):
        data = _pcapng([(1700000000.5, legit), (1700000001.25, spoof)], tsresol=res)
        frames = list(pcap.parse_capture(data))
        assert [round(ts, 2) for ts, _, _ in frames] == [1700000000.5, 1700000001.25]
        result = pcap.analyze_frames(frames, gateway_ip=GW[0])
        assert [a.kind for a in result.alerts] == ["gateway_arp_spoof"]
        assert result.gateway_source == "argument" and result.gateway_mac == GW[1]


def test_vlan_and_linux_cooked_frames():
    claim = arp(2, ATTACKER[1], "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1")
    tagged = bytes.fromhex("ffffffffffff") + bytes.fromhex(ATTACKER[1].replace(":", "")) + \
        struct.pack("!HHH", 0x8100, 42, 0x0806) + claim
    f = pcap.decode(pcap.LINKTYPE_ETHERNET, tagged)
    assert f.event == pcap.ArpClaim("10.0.0.5", ATTACKER[1])
    sll = struct.pack("!HHH", 0, 1, 6) + bytes.fromhex(ATTACKER[1].replace(":", "")) + b"\0\0" + \
        struct.pack("!H", 0x0806) + claim
    assert pcap.decode(pcap.LINKTYPE_LINUX_SLL, sll).event == pcap.ArpClaim("10.0.0.5", ATTACKER[1])


def test_malformed_input_never_crashes():
    for junk in (b"", b"\x00" * 13, b"\xff" * 60, ether(GW[1], ATTACKER[1], 0x0800, b"\x45\x00")):
        assert pcap.decode(1, junk).event is None
    with pytest.raises(pcap.CaptureError):
        list(pcap.parse_capture(b"not a capture file at all, really"))
    # A truncated final record is dropped, not a crash.
    path_bytes = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + \
        struct.pack("<IIII", 1, 0, 100, 100) + b"\0" * 10
    assert list(pcap.parse_capture(path_bytes)) == []


def test_dispatch_respects_watchers_and_local_ips():
    from netguard.detect import PortScanDetector
    assert pcap.dispatch(pcap.TcpSyn("1.1.1.1", "2.2.2.2", 22), 0.0, pcap.Watchers()) is None
    w = pcap.Watchers(port_scan=PortScanDetector(threshold=2))
    assert pcap.dispatch(pcap.TcpSyn("9.9.9.9", "10.0.0.2", 22), 0.0, w, {"10.0.0.1"}) is None
    pcap.dispatch(pcap.TcpSyn("9.9.9.9", "10.0.0.1", 22), 0.0, w, {"10.0.0.1"})
    assert pcap.dispatch(pcap.TcpSyn("9.9.9.9", "10.0.0.1", 23), 0.1, w, {"10.0.0.1"}).kind == "port_scan"


def test_cli_validate_and_pcap(tmp_path, capsys):
    from netguard.cli import main
    main(["--db", str(tmp_path / "x.db"), "validate"])
    assert f"{len(SCENARIOS)}/{len(SCENARIOS)} passed" in capsys.readouterr().out
    main(["--db", str(tmp_path / "x.db"), "simulate", "-o", str(tmp_path), "--scenario", "rogue_dhcp"])
    main(["--db", str(tmp_path / "x.db"), "pcap", str(tmp_path / "rogue_dhcp.pcap"), "--import"])
    out = capsys.readouterr().out
    assert "rogue_dhcp" in out and "Imported 2 alert(s)" in out
    from netguard.store import Store
    with Store(tmp_path / "x.db") as s:
        assert {a.kind for a in s.recent_alerts()} == {"rogue_dhcp", "dhcp_server_learned"}
