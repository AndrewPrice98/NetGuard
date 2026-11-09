import pytest

from netguard import oui


@pytest.fixture(autouse=True)
def isolated_oui(tmp_path, monkeypatch):
    """Never read or write the real ~/.netguard vendor list during tests."""
    monkeypatch.setattr(oui, "DATA_DIR", tmp_path)
    monkeypatch.setattr(oui, "OUI_FILE", tmp_path / "oui.txt")
    oui._table.cache_clear()
    yield
    oui._table.cache_clear()
