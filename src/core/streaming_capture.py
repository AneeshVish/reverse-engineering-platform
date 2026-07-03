"""SSE and WebSocket streaming capture helpers for mitmproxy flows."""

import json
import re
from typing import Dict, List, Any, Optional

SSE_CT = "text/event-stream"
WS_CT = "application/octet-stream"


def is_sse(flow: Dict) -> bool:
    rh = _headers(flow.get("resp_headers") or {})
    return SSE_CT in rh.get("content-type", "").lower()


def is_websocket(flow: Dict) -> bool:
    rh = _headers(flow.get("resp_headers") or {})
    ct = rh.get("content-type", "").lower()
    url = (flow.get("url") or "").lower()
    return "websocket" in ct or url.startswith("ws://") or url.startswith("wss://")


def mitm_streaming_args() -> List[str]:
    """Extra mitmdump args for large/streaming bodies (SSE).

    Use a 1MB threshold — NOT `1`, which would stream nearly every body and
    break req_body/resp_body capture in the addon.
    """
    return ["--set", "stream_large_bodies=1048576"]


def parse_sse_events(body: str) -> List[Dict[str, Any]]:
    """Parse SSE body into [{event, data, id}] chunks."""
    if not body:
        return []
    events = []
    current = {"event": "message", "data": [], "id": ""}
    for line in body.splitlines():
        if line.startswith("data:"):
            current["data"].append(line[5:].lstrip())
        elif line.startswith("event:"):
            current["event"] = line[6:].strip()
        elif line.startswith("id:"):
            current["id"] = line[3:].strip()
        elif line.strip() == "":
            if current["data"]:
                events.append({
                    "event": current["event"],
                    "data": "\n".join(current["data"]),
                    "id": current["id"],
                })
            current = {"event": "message", "data": [], "id": ""}
    if current["data"]:
        events.append({
            "event": current["event"],
            "data": "\n".join(current["data"]),
            "id": current["id"],
        })
    return events


def extract_sse_tokens(body: str) -> List[str]:
    """Extract token strings from SSE JSON payloads (LLM streaming)."""
    tokens = []
    for ev in parse_sse_events(body):
        data = ev.get("data", "")
        # Try JSON
        try:
            obj = json.loads(data)
            for key in ("token", "text", "delta", "content", "completion"):
                if key in obj:
                    val = obj[key]
                    if isinstance(val, str):
                        tokens.append(val)
                    elif isinstance(val, dict) and "text" in val:
                        tokens.append(val["text"])
        except (json.JSONDecodeError, TypeError):
            if data and not data.startswith("{"):
                tokens.append(data)
    return tokens


def enrich_flow(flow: Dict) -> Dict:
    """Add streaming metadata to a flow dict."""
    out = dict(flow)
    body = flow.get("resp_body") or ""
    if is_sse(flow):
        out["stream_type"] = "sse"
        out["sse_events"] = parse_sse_events(body)
        out["sse_token_count"] = len(extract_sse_tokens(body))
    elif is_websocket(flow):
        out["stream_type"] = "websocket"
    else:
        out["stream_type"] = "none"
    return out


def format_stream_summary(flow: Dict) -> str:
    enriched = enrich_flow(flow)
    st = enriched.get("stream_type", "none")
    if st == "sse":
        n = enriched.get("sse_token_count", 0)
        ev = len(enriched.get("sse_events", []))
        return f"SSE stream: {ev} events, ~{n} token chunks"
    if st == "websocket":
        return "WebSocket connection"
    return ""


def _headers(hdrs):
    return {k.lower(): v for k, v in (hdrs or {}).items()}
