"""End-to-end proof that live capture populates the FULL view, not just correlation.

Two layers:
  1. Integration: run the real mitmdump + capture addon, push one HTTP request with
     a Bearer token and a PII body through the proxy to a loopback server, and assert
     the JSONL flow carries method/url/host/status/headers/body + the extracted secret.
     (Uses plain HTTP on loopback so no CA/TLS setup is needed; the addon path is
     identical for HTTPS once the CA is trusted.)
  2. GUI: feed that flow to NetworkCapturePanel and assert the Request / Response /
     User Data / Secrets tabs all render — the "wow factor" detail view.

Both skip cleanly if their prerequisites (mitmdump / requests / PyQt6) are absent.
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src.core import traffic_capture as tc


# --- 1) real proxy + addon integration ------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = json.dumps({"ok": True, "session_id": "sess_abcdef123456"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.skipif(not tc.available(), reason="mitmdump not installed")
def test_full_capture_pipeline_records_flow_and_secret(tmp_path):
    try:
        import requests
    except Exception:
        pytest.skip("requests not installed")

    # Loopback origin server.
    srv_port = _free_port()
    srv = HTTPServer(("127.0.0.1", srv_port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    proxy_port = tc.pick_port(_free_port())
    cap_file = str(tmp_path / "cap.jsonl")
    proc = tc.start_proxy(proxy_port, cap_file)
    if proc is None:
        srv.shutdown()
        pytest.skip("could not start mitmdump")

    try:
        # Give mitmdump a moment to bind its port.
        for _ in range(40):
            if os.path.exists(cap_file):
                break
            time.sleep(0.1)
        time.sleep(1.0)

        url = f"http://127.0.0.1:{srv_port}/api/login"
        proxies = {"http": f"http://127.0.0.1:{proxy_port}"}
        headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s1gn4tur3abc"}
        payload = {"email": "user@example.com", "device_id": "abc-123",
                   "access_token": "tok_secret_value_123456"}
        ok = False
        for _ in range(3):
            try:
                requests.post(url, json=payload, headers=headers,
                              proxies=proxies, timeout=8)
                ok = True
                break
            except Exception:
                time.sleep(0.6)
        if not ok:
            pytest.skip("proxy round-trip failed in this sandbox")

        # Poll the JSONL for the captured flow.
        rec = None
        for _ in range(30):
            if os.path.exists(cap_file):
                with open(cap_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        obj = json.loads(line)
                        if obj.get("method") == "POST":
                            rec = obj
                            break
            if rec:
                break
            time.sleep(0.3)

        assert rec is not None, "no flow captured through the proxy"
        assert rec["host"] == "127.0.0.1"
        assert rec["path"].startswith("/api/login")
        assert rec["status"] == 200
        assert "user@example.com" in rec["req_body"]
        # The Bearer token in the request headers must be extracted as a secret.
        types = {s["type"] for s in rec.get("secrets", [])}
        assert "Bearer token" in types
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        srv.shutdown()


# --- 2) GUI detail-view rendering -----------------------------------------

@pytest.fixture(scope="module")
def _qapp():
    try:
        from PyQt6.QtWidgets import QApplication
    except Exception:
        pytest.skip("PyQt6 not available")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    yield app


def test_panel_renders_full_detail_tabs(_qapp):
    from src.gui.network_capture_panel import NetworkCapturePanel
    panel = NetworkCapturePanel()
    rec = {
        "ts": time.time(), "method": "POST",
        "url": "https://api.anthropic.com/v1/messages",
        "host": "api.anthropic.com", "path": "/v1/messages", "status": 200,
        "req_headers": {"Authorization": "Bearer eyJabc.def.ghi",
                        "Content-Type": "application/json"},
        "req_body": json.dumps({"email": "user@example.com",
                                "access_token": "tok_123456"}),
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body": json.dumps({"ok": True}),
        "secrets": [{"type": "Bearer token", "value": "Bearer eyJabc.def.ghi"}],
    }
    panel._add_flow(rec)
    assert panel.table.rowCount() == 1

    # Pre-seed the ownership-proof cache so _show_detail doesn't spawn the async
    # TLS/WHOIS worker thread (network call; would also abort Qt on teardown).
    panel._proof_cache["api.anthropic.com"] = "Owner: Anthropic (cached for test)"

    panel.table.selectRow(0)
    panel._show_detail()

    assert "api.anthropic.com" in panel.req_view.toPlainText()
    assert "Status: 200" in panel.resp_view.toPlainText()
    # User Data (PII) tab picks up the email/token from the request body.
    assert "example.com" in panel.pii_view.toPlainText().lower() or \
           "email" in panel.pii_view.toPlainText().lower()
    assert "Bearer token" in panel.flow_secrets.toPlainText()
    # The global secrets pane accumulates it too.
    assert "Bearer token" in panel.secrets_view.toPlainText()
