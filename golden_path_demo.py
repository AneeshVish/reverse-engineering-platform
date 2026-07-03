#!/usr/bin/env python3
"""Golden-path demo script — validates RED TEAM pipeline modules without GUI.

Run: .venv/bin/python golden_path_demo.py
"""

from src.core.evidence_store import reset_session_store, session_store
from src.core import client_architecture_intel as cai
from src.core import behavior_infer, behavior_metrics, request_correlation
from src.core import behavior_timeline, telemetry_parser, streaming_capture
from src.core import access_path_engine, blue_team, engagement_report


def main():
    reset_session_store()
    print("=== RED TEAM Golden Path Demo ===\n")

    # Simulated capture flows (Claude-like pattern, sanitized)
    flows = [{
        "ts": 1.0, "method": "POST", "host": "claude.ai",
        "path": "/api/organizations/org/chat_conversations/conv/completion",
        "url": "https://claude.ai/api/organizations/org/chat_conversations/conv/completion",
        "status": 200,
        "req_body": '{"message_content":"Hello"}',
        "resp_headers": {
            "content-type": "text/event-stream",
            "x-request-id": "req_demo001",
            "cf-ray": "654321-BLR",
            "traceparent": "00-abc-def-01",
        },
        "resp_body": 'data: {"token":"Hi"}\n\n',
        "ttft_ms": 150,
    }, {
        "ts": 1.5, "method": "POST",
        "host": "browser-intake-us5-datadoghq.com",
        "path": "/api/v2/rum",
        "url": "https://browser-intake-us5-datadoghq.com/api/v2/rum",
        "req_body": '{"session":{"id":"sess-demo"},"action":{"id":"act-send"}}',
        "resp_headers": {}, "resp_body": "", "status": 200,
    }]

    for f in flows:
        enriched = streaming_capture.enrich_flow(f)
        if enriched.get("stream_type") == "sse":
            print(streaming_capture.format_stream_summary(enriched))

    print("\n--- Behavior Inference (L3) ---")
    print(behavior_infer.format_report(flows))

    print("\n--- Behavior Metrics (L2) ---")
    print(behavior_metrics.format_report(behavior_metrics.measure_flows(flows)))

    print("\n--- Request Correlation ---")
    print(request_correlation.format_report(request_correlation.correlate(flows)))

    print("\n--- Telemetry ---")
    telem = telemetry_parser.analyze_flows(flows)
    print(telemetry_parser.format_report(telem))

    tl = behavior_timeline.BehaviorTimeline()
    tl.merge_flows(flows)
    print("\n--- Behavior Timeline ---")
    print(tl.format_report())

    intel = {"endpoints": ["/api/admin/health"], "hosts": ["staging.claude.ai"],
             "feature_flags": [], "hits": []}
    cands = access_path_engine.discover(architecture_intel=intel, flows=flows)
    print("\n--- Access Paths ---")
    print(access_path_engine.format_report(cands))

    cai.to_evidence({"hits": [{"category": "ml_inference", "keyword": "inference",
                               "source": "demo", "context": "inference service"}],
                     "endpoints": ["/v1/messages"]})
    print("\n--- Evidence Chain ---")
    print(session_store().format_report())

    print("\n--- BLUE TEAM ---")
    print(blue_team.format_report(blue_team.recommendations_from_evidence()))

    out = "/tmp/re_engagement_demo.html"
    engagement_report.save_report(out, flows=flows,
                                  behavior_infer_text=behavior_infer.format_report(flows),
                                  timeline_text=tl.format_report())
    print(f"\nReport saved: {out}")
    print("\nDemo complete.")


if __name__ == "__main__":
    main()
