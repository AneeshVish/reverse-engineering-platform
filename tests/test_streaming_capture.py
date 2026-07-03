"""Tests for streaming capture (SSE)."""

from src.core import streaming_capture as sc


SSE_BODY = 'data: {"token":"Hello"}\n\ndata: {"token":" world"}\n\n'


def test_parse_sse_events():
    events = sc.parse_sse_events(SSE_BODY)
    assert len(events) >= 2
    assert "Hello" in events[0]["data"]


def test_extract_sse_tokens():
    tokens = sc.extract_sse_tokens(SSE_BODY)
    assert any("Hello" in t for t in tokens)


def test_is_sse():
    flow = {"resp_headers": {"content-type": "text/event-stream"}, "resp_body": SSE_BODY}
    assert sc.is_sse(flow)
    enriched = sc.enrich_flow(flow)
    assert enriched["stream_type"] == "sse"
    assert enriched["sse_token_count"] >= 1
