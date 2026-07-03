"""Tests for server_proof: proving a host is a real production server from the
signals the server itself returns — NOT from other users' (unobservable) traffic.
"""

from src.core import server_proof as sp


def _flow(status=200, resp_headers=None, method="POST"):
    return {"method": method, "url": "https://api.x.com/v1", "host": "api.x.com",
            "status": status, "resp_headers": resp_headers or {}}


def test_no_signals_when_no_response_headers():
    assert sp.production_signals([_flow(resp_headers={})]) == []


def test_detects_trace_org_ratelimit_and_edge():
    flows = [_flow(resp_headers={
        "request-id": "req_011CcdNz",
        "anthropic-organization-id": "891e0807-2006",
        "anthropic-ratelimit-requests-remaining": "49",
        "cf-ray": "a14e4ca78ad5-BOM",
        "cf-cache-status": "DYNAMIC",
        "server-timing": "x-originResponse;dur=73",
        "Server": "cloudflare",
        "Date": "Thu, 02 Jul 2026 14:21:53 GMT",
    })]
    cats = {s["category"] for s in sp.production_signals(flows)}
    assert "Per-request trace ID" in cats
    assert "Tenant / organization scoping" in cats
    assert "Rate-limit / quota enforcement" in cats
    assert "Edge / CDN delivery" in cats
    assert "Origin processing time" in cats
    assert "Live server clock" in cats


def test_header_matching_is_case_insensitive():
    sigs = sp.production_signals([_flow(resp_headers={"X-Cache": "HIT"})])
    assert any(s["category"] == "Edge / CDN delivery" for s in sigs)
    # Original header name is preserved in the evidence for display.
    assert sigs[0]["evidence"][0][0] == "X-Cache"


def test_activity_summary_counts_methods_and_statuses():
    flows = [_flow(status=200, method="POST"), _flow(status=200, method="GET"),
             _flow(status=429, method="POST")]
    summ = sp.activity_summary(flows)
    assert summ["count"] == 3
    assert summ["methods"] == ["GET", "POST"]
    assert "200×2" in summ["status_str"] and "429×1" in summ["status_str"]


def test_format_is_honest_about_unobservable_third_party_traffic():
    text = sp.format_server_proof("api.x.com", [_flow(resp_headers={"request-id": "r1"})],
                                  ownership_proof="Owner: X Corp", static_confirmed=True)
    assert "SERVER:  api.x.com" in text
    assert "CONFIRMED by live traffic" in text
    assert "Owner: X Corp" in text
    assert "PRODUCTION-SERVER PROOF" in text
    # The core honesty: we cannot see other users' traffic to this server.
    low = text.lower()
    assert "other users" in low or "wiretapping" in low


def test_format_handles_empty_flows():
    text = sp.format_server_proof("api.x.com", [], ownership_proof=None)
    assert "No response headers captured" in text
    assert "No requests captured" in text
    # Ownership proof still shows a resolving placeholder rather than crashing.
    assert "Resolving owner" in text


def test_truncates_absurdly_long_header_values():
    huge = "z" * 5000
    sigs = sp.production_signals([_flow(resp_headers={"server-timing": huge})])
    val = sigs[0]["evidence"][0][1]
    assert len(val) < 200 and val.endswith("…")
