"""Tests for direct server access / credential harvest."""

from src.core.server_access import (
    harvest_credentials, pick_best_flow, DirectAccessSession, HarvestedCredential,
)


def test_harvest_bearer_from_flow():
    flows = [{
        "host": "claude.ai", "url": "https://claude.ai/api/test",
        "method": "POST",
        "secrets": [{"type": "Bearer token", "value": "Bearer eyJ.test.token"}],
        "req_headers": {"Authorization": "Bearer eyJ.test.token"},
    }]
    creds = harvest_credentials(flows)
    assert len(creds) >= 1
    assert "Bearer" in creds[0].value or "eyJ" in creds[0].value


def test_pick_best_flow_prefers_authenticated_post():
    flows = [
        {"method": "GET", "host": "claude.ai", "path": "/favicon.ico"},
        {"method": "POST", "host": "claude.ai", "path": "/api/chat",
         "secrets": [{"type": "Bearer token", "value": "Bearer abc"}],
         "req_body": "{}", "url": "https://claude.ai/api/chat"},
    ]
    best = pick_best_flow(flows)
    assert best["path"] == "/api/chat"


def test_session_configure_without_cred():
    s = DirectAccessSession()
    creds = s.configure(flows=[], base_url="https://api.example.com/v1/x", app_name="Claude")
    assert creds == []
    assert not s.state.url or s.state.url == "https://api.example.com/v1/x"


def test_establish_uses_access_call_record(monkeypatch):
    s = DirectAccessSession()
    cred = HarvestedCredential(cred_type="Authorization", value="Bearer tok", host="api.example.com")
    s.configure(
        flows=[{
            "method": "POST",
            "host": "api.example.com",
            "path": "/v1/messages",
            "url": "https://api.example.com/v1/messages",
            "secrets": [{"type": "Bearer token", "value": "Bearer tok"}],
            "req_headers": {"Authorization": "Bearer tok"},
            "req_body": "{}",
        }],
        app_name="Claude",
        credential=cred,
    )
    monkeypatch.setattr(
        "src.core.server_access.http_request",
        lambda *a, **k: {"status": 401, "body": '{"error":"x-api-key required"}', "error": ""},
    )
    out = s.establish()
    assert out["ok"] is True
    assert out["proven"] is True
    assert out["result"].status == 401
