"""Tests for L2 correlation modules."""

import time
from src.core import behavior_metrics, request_correlation, behavior_timeline
from src.core import telemetry_parser, function_request_correlation as frc


def _sse_flow():
    return {
        "ts": time.time(), "method": "POST", "host": "api.example.com",
        "path": "/v1/messages", "status": 200,
        "resp_headers": {"content-type": "text/event-stream",
                         "x-request-id": "req_abc123"},
        "resp_body": 'data: {"token":"Hi"}\n\n',
        "ttft_ms": 120,
    }


def test_behavior_metrics_sse():
    m = behavior_metrics.measure_flows([_sse_flow()])
    assert m["sse_count"] == 1


def test_request_correlation_shared_id():
    f1 = _sse_flow()
    f2 = dict(_sse_flow())
    f2["path"] = "/v1/complete"
    r = request_correlation.correlate([f1, f2])
    assert r["unique_ids"] >= 1


def test_behavior_timeline_merge():
    tl = behavior_timeline.BehaviorTimeline()
    tl.merge_flows([_sse_flow()])
    text = tl.format_report()
    assert "network_request" in text


def test_telemetry_detects_datadog():
    flow = {
        "host": "browser-intake-us5-datadoghq.com",
        "path": "/api/v2/rum",
        "url": "https://browser-intake-us5-datadoghq.com/api/v2/rum",
        "req_body": '{"session":{"id":"sess-1"},"action":{"id":"act-1"}}',
        "resp_body": "", "ts": time.time(),
    }
    r = telemetry_parser.analyze_flows([flow])
    assert "datadog" in r.get("vendors", [])


def test_function_request_correlation_match():
    ts = time.time()
    hooks = [{"type": "net_hook", "api": "fetch", "url": "https://api.example.com/v1/messages",
              "method": "POST", "ts": ts, "stack": "Error\n at sendMessage"}]
    flows = [_sse_flow()]
    flows[0]["ts"] = ts
    cor = frc.correlate(hooks, flows, window_sec=5.0)
    assert cor[0]["matched"]
