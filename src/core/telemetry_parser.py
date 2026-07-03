"""Telemetry parsing — Datadog RUM, Sentry, GA, Amplitude."""

import json
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

VENDORS = {
    "datadog": [
        r"datadoghq\.com",
        r"browser-intake.*datadoghq",
        r"dd\.og\.",
    ],
    "sentry": [r"sentry\.io", r"o\d+\.ingest\.sentry"],
    "google_analytics": [r"google-analytics\.com", r"googletagmanager", r"/g/collect"],
    "amplitude": [r"amplitude\.com", r"api\.amplitude"],
    "segment": [r"segment\.io", r"api\.segment"],
    "mixpanel": [r"mixpanel\.com"],
}

_SESSION_RE = re.compile(r'"(?:session[_\.]?id|sessionId)"\s*:\s*"([^"]+)"', re.I)
_TRACE_RE = re.compile(r'"(?:trace[_\.]?id|traceId)"\s*:\s*"?(\d+)"?', re.I)
_ACTION_RE = re.compile(r'"(?:action[_\.]?id|actionId)"\s*:\s*"([^"]+)"', re.I)
_VIEW_RE = re.compile(r'"(?:view[_\.]?id|viewId)"\s*:\s*"([^"]+)"', re.I)


def detect_vendor(url: str, host: str = "") -> Optional[str]:
    target = (url or "") + " " + (host or "")
    for vendor, patterns in VENDORS.items():
        for pat in patterns:
            if re.search(pat, target, re.I):
                return vendor
    return None


def parse_payload(body: str) -> Dict[str, Any]:
    """Extract session/trace/action IDs from telemetry JSON body."""
    out = {"session_id": "", "trace_id": "", "action_id": "", "view_id": "", "raw_keys": []}
    if not body:
        return out
    text = body[:50000]
    for regex, key in [
        (_SESSION_RE, "session_id"), (_TRACE_RE, "trace_id"),
        (_ACTION_RE, "action_id"), (_VIEW_RE, "view_id"),
    ]:
        m = regex.search(text)
        if m:
            out[key] = m.group(1)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            out["raw_keys"] = list(obj.keys())[:20]
            for k in ("session", "action", "view"):
                if k in obj and isinstance(obj[k], dict):
                    out[f"{k}_id"] = out[f"{k}_id"] or str(obj[k].get("id", ""))
    except (json.JSONDecodeError, TypeError):
        pass
    return out


def analyze_flows(flows: List[Dict]) -> Dict[str, Any]:
    """Find telemetry flows and extract IDs."""
    telemetry_flows = []
    sessions = set()
    traces = set()

    for f in flows or []:
        url = f.get("url", "") or ""
        host = f.get("host", "") or ""
        vendor = detect_vendor(url, host)
        if not vendor:
            continue
        body = (f.get("req_body") or "") + (f.get("resp_body") or "")
        parsed = parse_payload(body)
        if parsed.get("session_id"):
            sessions.add(parsed["session_id"])
        if parsed.get("trace_id"):
            traces.add(parsed["trace_id"])
        telemetry_flows.append({
            "vendor": vendor,
            "host": host,
            "path": f.get("path", ""),
            "ts": f.get("ts", 0),
            **parsed,
        })

    return {
        "telemetry_flows": telemetry_flows,
        "session_ids": sorted(sessions),
        "trace_ids": sorted(traces),
        "vendors": sorted({t["vendor"] for t in telemetry_flows}),
    }


def correlate_with_api(telemetry: Dict, api_flows: List[Dict]) -> List[Dict]:
    """Match telemetry trace/session IDs to API flow headers."""
    matches = []
    trace_set = set(telemetry.get("trace_ids", []))
    for f in api_flows or []:
        rh = {k.lower(): v for k, v in (f.get("resp_headers") or {}).items()}
        for hk in ("x-datadog-trace-id", "traceparent", "x-request-id"):
            if hk in rh:
                val = rh[hk]
                if hk == "traceparent":
                    val = val.split("-")[1] if "-" in val else val
                if val in trace_set or any(val.endswith(t) for t in trace_set):
                    matches.append({
                        "telemetry_trace": val,
                        "api_host": f.get("host", ""),
                        "api_path": f.get("path", ""),
                    })
    return matches


def format_report(result: Dict[str, Any]) -> str:
    lines = ["TELEMETRY ANALYSIS", "=" * 60]
    if not result.get("telemetry_flows"):
        return lines[0] + "\n" + "=" * 60 + "\nNo telemetry flows detected yet."
    lines.append(f"Vendors: {', '.join(result.get('vendors', []))}")
    lines.append(f"Telemetry calls: {len(result['telemetry_flows'])}")
    lines.append(f"Unique sessions: {len(result.get('session_ids', []))}")
    lines.append(f"Unique traces: {len(result.get('trace_ids', []))}")
    for t in result["telemetry_flows"][:15]:
        lines.append(f"\n  [{t['vendor']}] {t['host']}{t['path']}")
        if t.get("session_id"):
            lines.append(f"    session: {t['session_id']}")
        if t.get("action_id"):
            lines.append(f"    action: {t['action_id']}")
    return "\n".join(lines)
