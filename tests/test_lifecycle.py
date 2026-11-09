"""Starting and stopping: busy ports, reusing a running copy, the Stop button."""

import socket
import threading
import time

import pytest

from netguard.cli import main
from netguard.store import Store
from netguard.web.server import (DashboardServer, _bind, running_netguard, serve,
                                 stop_running)
from tests.test_web import POST, FakeMonitor, request


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "life.db"
    Store(path).close()
    return path


def start(db, monitor=None):
    srv = DashboardServer(("127.0.0.1", 0), db, monitor, "")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_stop_button_needs_csrf_header_then_shuts_down(db):
    srv = start(db)
    port = srv.server_port
    assert request(srv, "POST", "/api/shutdown")[0] == 403  # no X-NetGuard header
    assert running_netguard(port) is not None
    assert request(srv, "POST", "/api/shutdown", POST)[0] == 200
    time.sleep(0.8)
    assert srv.stopped_by_user
    srv.server_close()
    assert running_netguard(port) is None


def test_stop_running_helper(db):
    srv = start(db)
    assert stop_running(srv.server_port)
    time.sleep(0.8)
    srv.server_close()
    assert not stop_running(srv.server_port)  # nothing left to stop


def test_busy_port_falls_back_to_next_free(db, capsys):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    try:
        assert running_netguard(port) is None  # something, but not NetGuard
        httpd = _bind("127.0.0.1", port, db, None, "", reuse_existing=True, open_browser=False)
        assert httpd.server_port != port
        assert "another program" in capsys.readouterr().out
        httpd.server_close()
    finally:
        blocker.close()


def test_serve_reuses_a_running_monitor(db, capsys):
    srv = start(db, FakeMonitor())
    try:
        # A second `serve` on the same port opens the running copy and returns.
        serve(db, "127.0.0.1", srv.server_port, monitor=FakeMonitor(), reuse_existing=True)
        assert "already running" in capsys.readouterr().out
        # The demo (view-only) never reuses a monitor: it moves to another port.
        httpd = _bind("127.0.0.1", srv.server_port, db, None, "", False, False)
        assert httpd.server_port != srv.server_port
        assert "another NetGuard" in capsys.readouterr().out
        httpd.server_close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_stop_and_quick_start(db, capsys, tmp_path):
    srv = start(db)
    main(["--db", str(tmp_path / "x.db"), "stop", "--port", str(srv.server_port)])
    assert "Stopped NetGuard" in capsys.readouterr().out
    time.sleep(0.8)
    srv.server_close()
    with pytest.raises(SystemExit):
        main(["--db", str(tmp_path / "x.db"), "stop", "--port", str(srv.server_port)])
    main([])
    assert "python -m netguard demo" in capsys.readouterr().out
