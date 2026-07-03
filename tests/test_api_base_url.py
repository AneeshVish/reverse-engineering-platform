"""Tests for automatic Access Path base URL selection."""

from src.core import api_base_url as abu


def test_capture_post_api_beats_get_favicon():
    flows = [
        {"method": "GET", "host": "claude.ai", "path": "/favicon.ico", "status": 200},
        {"method": "POST", "host": "claude.ai",
         "path": "/api/organizations/o/chat_conversations/c/completion",
         "status": 200,
         "req_headers": {"Content-Type": "application/json"},
         "req_body": '{"message":"hi"}',
         "resp_headers": {"content-type": "text/event-stream"}},
    ]
    s = abu.suggest(flows=flows, app_name="Claude")
    assert s is not None
    assert s.source == "capture"
    assert "completion" in s.url
    assert "favicon" not in s.url


def test_ignores_microsoft_graph_static():
    intel = {"endpoints": ["https://graph.microsoft.com/v1.0/me"], "hosts": ["graph.microsoft.com"]}
    s = abu.suggest(architecture_intel=intel, app_name="Claude")
    assert s is None or "graph.microsoft.com" not in s.url


def test_live_anthropic_socket_picks_claude_api():
    live = [{"raddr": "160.79.104.10:443", "org": "Anthropic, PBC", "rdns": ""}]
    s = abu.suggest(live_conns=live, app_name="Claude.app", architecture_intel={})
    assert s is not None
    assert "anthropic.com" in s.url or "claude.ai" in s.url
    assert s.source in ("live_socket", "canonical")


def test_tracker_host_excluded():
    flows = [{"method": "POST", "host": "browser-intake-us5-datadoghq.com",
              "path": "/api/v2/rum", "status": 200, "req_body": "{}"}]
    s = abu.suggest(flows=flows, app_name="Claude")
    assert s is None or "datadog" not in s.url


def test_github_feature_route_normalized():
    url = "https://claude.ai/v1/code/github/batch-branch-status"
    flows = [{
        "method": "POST", "host": "claude.ai", "path": "/v1/code/github/batch-branch-status",
        "url": url, "status": 200,
        "req_headers": {"Content-Type": "application/json"},
        "req_body": '{"repos":[]}',
    }]
    s = abu.suggest(flows=flows, app_name="Claude")
    assert s is not None
    assert s.url == "https://api.anthropic.com/v1/messages"
    assert "github" not in s.url


def test_mcp_toolbox_url_normalized_to_stable_api():
    mcp = ("https://claude.ai/v1/toolbox/shttp/mcp/"
           "41437525-9e10-404d-8423-0eec4d9abd2e")
    flows = [{
        "method": "POST", "host": "claude.ai",
        "path": "/v1/toolbox/shttp/mcp/41437525-9e10-404d-8423-0eec4d9abd2e",
        "url": mcp, "status": 200,
        "req_headers": {"Content-Type": "application/json"},
        "req_body": "{}",
    }]
    s = abu.suggest(flows=flows, app_name="Claude")
    assert s is not None
    assert "mcp" not in s.url.lower()
    assert "41437525" not in s.url
    assert "anthropic.com" in s.url or "completion" in s.url or "messages" in s.url


def test_sse_stream_scores_high():
    flows = [{
        "method": "POST", "host": "api.anthropic.com", "path": "/v1/messages",
        "url": "https://api.anthropic.com/v1/messages", "status": 200,
        "resp_headers": {"content-type": "text/event-stream"},
        "req_headers": {"Content-Type": "application/json"},
        "req_body": '{"model":"claude"}',
    }]
    s = abu.suggest(flows=flows, app_name="Claude")
    assert s.url == "https://api.anthropic.com/v1/messages"
