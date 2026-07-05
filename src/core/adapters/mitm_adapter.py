"""Convert mitmproxy JSONL flow records to PlaintextEvent(s)."""

import time
from typing import Any, Dict, List
from urllib.parse import urlparse

from src.core.evidence_store import PlaintextEvent


def _ns(ts: float) -> int:
    if ts and ts > 1e12:
        return int(ts)
    return int((ts or time.time()) * 1_000_000_000)


def _host_port(rec: Dict[str, Any]) -> tuple:
    host = rec.get("host", "") or ""
    port = 443
    url = rec.get("url", "") or ""
    if url:
        try:
            p = urlparse(url)
            host = host or (p.hostname or "")
            if p.port:
                port = p.port
            elif p.scheme == "http":
                port = 80
        except Exception:
            pass
    return host, port


def flow_to_plaintext_events(rec: Dict[str, Any]) -> List[PlaintextEvent]:
    """One mitm flow → request + optional response PlaintextEvents."""
    if not rec or "method" not in rec:
        return []
    host, port = _host_port(rec)
    ts = _ns(rec.get("ts", time.time()))
    base_meta = {
        "flow_id": rec.get("url", ""),
        "method": rec.get("method", ""),
        "url": rec.get("url", ""),
        "path": rec.get("path", ""),
        "status": rec.get("status"),
        "secrets": rec.get("secrets", []),
    }
    events = []
    req_body = (rec.get("req_body") or "").encode("utf-8", errors="replace")
    req_hdr = "\n".join(
        f"{k}: {v}" for k, v in (rec.get("req_headers") or {}).items()
    ).encode("utf-8", errors="replace")
    req_payload = req_hdr + b"\n\n" + req_body if req_body or req_hdr else b""
    events.append(PlaintextEvent(
        timestamp_ns=ts,
        source_plane="mitmproxy",
        pid=0,
        uid=0,
        process_comm="mitmproxy",
        target_host=host,
        target_port=port,
        payload_type="request",
        raw_payload=req_payload,
        metadata=dict(base_meta),
    ))
    if rec.get("resp_body") is not None or rec.get("resp_headers"):
        resp_body = (rec.get("resp_body") or "").encode("utf-8", errors="replace")
        resp_hdr = "\n".join(
            f"{k}: {v}" for k, v in (rec.get("resp_headers") or {}).items()
        ).encode("utf-8", errors="replace")
        resp_payload = resp_hdr + b"\n\n" + resp_body if resp_body or resp_hdr else b""
        events.append(PlaintextEvent(
            timestamp_ns=ts,
            source_plane="mitmproxy",
            pid=0,
            uid=0,
            process_comm="mitmproxy",
            target_host=host,
            target_port=port,
            payload_type="response",
            raw_payload=resp_payload,
            metadata={**base_meta, "status": rec.get("status")},
        ))
    return events
