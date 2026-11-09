import pytest

from netguard import oui
from netguard.fingerprint import TYPE_LABELS, classify
from netguard.models import Host

OUI_SAMPLE = """\
OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai

F8-79-0A   (hex)		ARRIS Group, Inc.
F8790A     (base 16)		ARRIS Group, Inc.
"""


# (conftest.py points the OUI file at a temp dir for every test.)

# --- OUI ----------------------------------------------------------------------
def test_parse_oui_text():
    assert oui.parse_oui_text(OUI_SAMPLE) == {
        "28:6f:b9": "Nokia Shanghai Bell Co., Ltd.",
        "f8:79:0a": "ARRIS Group, Inc.",
    }


def test_builtin_fallback_without_download():
    assert oui.lookup("b8:27:eb:00:00:01") == "Raspberry Pi"
    assert oui.lookup("f8:79:0a:00:00:01") == ""


def test_update_from_file_installs_registry(tmp_path):
    big = OUI_SAMPLE + "".join(f"00-{i // 256:02X}-{i % 256:02X}   (hex)\t\tVendor {i}\n"
                               for i in range(1200))
    src = tmp_path / "download.txt"
    src.write_text(big, encoding="utf-8")
    assert oui.update(src) == 1202
    assert oui.lookup("F8:79:0A:43:0D:31") == "ARRIS Group, Inc."


def test_update_rejects_garbage(tmp_path):
    src = tmp_path / "bad.txt"
    src.write_text("<html>Access denied</html>", encoding="utf-8")
    with pytest.raises(ValueError):
        oui.update(src)


# --- Fingerprinting -----------------------------------------------------------
@pytest.mark.parametrize("host, ports, expected", [
    (Host(mac="m", ip="10.0.0.1"), set(), "router"),
    (Host(mac="m", hostname="Johns-iPhone.lan"), set(), "phone"),
    (Host(mac="m", hostname="XBOX"), set(), "console"),
    (Host(mac="m", hostname="EPSON42060F"), {80, 443, 9100}, "printer"),
    (Host(mac="m", vendor="Raspberry Pi"), {22}, "sbc"),
    (Host(mac="m", hostname="Living-Room-TV"), set(), "tv"),
    (Host(mac="m"), {9100}, "printer"),
    (Host(mac="m"), {3389, 445}, "computer"),
    (Host(mac="m"), {22, 3306}, "server"),
    (Host(mac="m", vendor="randomized MAC"), set(), "mobile"),
    (Host(mac="m"), set(), "unknown"),
])
def test_classify(host, ports, expected):
    assert classify(host, ports, gateway_ip="10.0.0.1") == expected
    assert expected in TYPE_LABELS
