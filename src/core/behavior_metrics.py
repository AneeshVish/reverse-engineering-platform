"""Behavior metrics — TTFT, inter-token gap, retry/backoff, rate limits."""

import re
import statistics
from typing import Dict, List, Any, Optional

from src.core import streaming_capture as sc


def measure_flows(flows: List[Dict]) -> Dict[str, Any]:
    """Compute timing metrics from captured flows."""
    metrics = {
        "sse_flows": [],
        "ttft_ms": [],
        "inter_token_gaps_ms": [],
        "rate_limits": [],
        "retries": [],
        "latency_ms": [],
    }

    prev_by_host = {}
    for f in sorted(flows or [], key=lambda x: x.get("ts", 0)):
        ts = f.get("ts", 0)
        host = f.get("host", "")
        status = str(f.get("status", ""))
        rh = _ci(f.get("resp_headers") or {})

        # Response latency from mitm if available
        dur = f.get("duration_ms") or f.get("elapsed_ms")
        if dur:
            metrics["latency_ms"].append(float(dur))

        # Rate limit headers
        for hk, hv in rh.items():
            if "ratelimit" in hk or "retry-after" in hk:
                metrics["rate_limits"].append({"header": hk, "value": hv, "host": host})

        # Retry detection (429/503 followed by retry)
        if status in ("429", "503", "502"):
            metrics["retries"].append({"ts": ts, "status": status, "host": host, "path": f.get("path", "")})

        if sc.is_sse(f):
            enriched = sc.enrich_flow(f)
            events = enriched.get("sse_events", [])
            req_ts = ts
            if events:
                # TTFT: time from request to first SSE event (approx — same flow ts)
                ttft = f.get("ttft_ms")
                if ttft is None and f.get("resp_ts"):
                    ttft = (f["resp_ts"] - req_ts) * 1000
                if ttft is not None:
                    metrics["ttft_ms"].append(float(ttft))
                metrics["sse_flows"].append({
                    "host": host, "path": f.get("path", ""),
                    "events": len(events),
                    "tokens": enriched.get("sse_token_count", 0),
                })
                # Inter-token gaps from event timestamps if present
                gaps = f.get("token_gaps_ms") or []
                metrics["inter_token_gaps_ms"].extend(gaps)

        prev_by_host[host] = f

    summary = {
        "flow_count": len(flows or []),
        "sse_count": len(metrics["sse_flows"]),
        "ttft": _stats(metrics["ttft_ms"]),
        "inter_token_gap": _stats(metrics["inter_token_gaps_ms"]),
        "latency": _stats(metrics["latency_ms"]),
        "rate_limit_headers": metrics["rate_limits"][:20],
        "retry_events": metrics["retries"][:20],
        "sse_flows": metrics["sse_flows"][:10],
    }
    return summary


def _stats(vals: List[float]) -> Dict[str, Optional[float]]:
    if not vals:
        return {"count": 0, "min": None, "max": None, "mean": None, "p50": None}
    return {
        "count": len(vals),
        "min": round(min(vals), 2),
        "max": round(max(vals), 2),
        "mean": round(statistics.mean(vals), 2),
        "p50": round(statistics.median(vals), 2),
    }


def format_report(summary: Dict[str, Any]) -> str:
    lines = ["BEHAVIOR METRICS", "=" * 60]
    lines.append(f"Flows analyzed: {summary.get('flow_count', 0)}")
    lines.append(f"SSE streams: {summary.get('sse_count', 0)}")
    ttft = summary.get("ttft", {})
    if ttft.get("count"):
        lines.append(f"\nTime-to-first-token (ms): n={ttft['count']} "
                     f"mean={ttft['mean']} p50={ttft['p50']} min={ttft['min']} max={ttft['max']}")
    gap = summary.get("inter_token_gap", {})
    if gap.get("count"):
        lines.append(f"Inter-token gap (ms): n={gap['count']} mean={gap['mean']} p50={gap['p50']}")
    lat = summary.get("latency", {})
    if lat.get("count"):
        lines.append(f"Response latency (ms): n={lat['count']} mean={lat['mean']} p50={lat['p50']}")
    if summary.get("rate_limit_headers"):
        lines.append("\nRate-limit headers:")
        for r in summary["rate_limit_headers"][:10]:
            lines.append(f"  {r['header']}: {r['value']}  ({r['host']})")
    if summary.get("retry_events"):
        lines.append(f"\nRetry/rate-limit events: {len(summary['retry_events'])}")
    return "\n".join(lines)


def _ci(hdrs):
    return {k.lower(): v for k, v in (hdrs or {}).items()}
