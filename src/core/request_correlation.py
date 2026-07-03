"""Request ID and trace correlation across flows."""

import re
from collections import defaultdict
from typing import Dict, List, Any, Set

_ID_HEADERS = [
    "x-request-id", "request-id", "x-correlation-id", "x-amzn-requestid",
    "x-amzn-trace-id", "x-datadog-trace-id", "traceparent", "x-b3-traceid",
    "cf-ray", "x-github-request-id",
]
_REQ_ID_BODY = re.compile(r'"?(?:request[_-]?id|trace[_-]?id)"?\s*:\s*"([^"]+)"', re.I)
_REQ_PREFIX = re.compile(r"(req_[0-9A-Za-z]+)")


def extract_ids(flow: Dict) -> Dict[str, str]:
    """Extract correlation IDs from a flow's headers and body."""
    ids = {}
    rh = _ci(flow.get("resp_headers") or {})
    qh = _ci(flow.get("req_headers") or {})
    for h in _ID_HEADERS:
        if h in rh:
            ids[h] = _normalize_id(h, rh[h])
        if h in qh:
            ids[f"req:{h}"] = _normalize_id(h, qh[h])
    body = (flow.get("resp_body") or "") + (flow.get("req_body") or "")
    for m in _REQ_ID_BODY.finditer(body[:8000]):
        ids["body:request_id"] = m.group(1)
    for m in _REQ_PREFIX.finditer(body[:8000]):
        ids["body:req_prefix"] = m.group(1)
    return ids


def _normalize_id(header: str, val: str) -> str:
    if header == "traceparent":
        parts = val.split("-")
        return parts[1] if len(parts) > 1 else val
    return val.strip()


def correlate(flows: List[Dict]) -> Dict[str, Any]:
    """Build ID → flows mapping and cross-host spans."""
    id_map: Dict[str, List[Dict]] = defaultdict(list)
    flow_ids: List[Dict] = []

    for i, f in enumerate(flows or []):
        ids = extract_ids(f)
        entry = {"flow_index": i, "host": f.get("host", ""), "path": f.get("path", ""),
                 "method": f.get("method", ""), "ts": f.get("ts", 0), "ids": ids}
        flow_ids.append(entry)
        for key, val in ids.items():
            id_map[f"{key}={val}"].append(entry)

    spans = []
    for id_key, entries in id_map.items():
        hosts = {e["host"] for e in entries}
        if len(entries) >= 2:
            spans.append({
                "id": id_key,
                "count": len(entries),
                "hosts": sorted(hosts),
                "cross_host": len(hosts) >= 2,
                "entries": entries[:10],
            })

    spans.sort(key=lambda s: (-int(s["cross_host"]), -s["count"]))
    return {
        "flow_ids": flow_ids,
        "spans": spans,
        "unique_ids": len(id_map),
        "cross_host_spans": sum(1 for s in spans if s["cross_host"]),
    }


def format_report(result: Dict[str, Any]) -> str:
    lines = ["REQUEST CORRELATION TIMELINE", "=" * 60]
    lines.append(f"Unique correlation IDs: {result.get('unique_ids', 0)}")
    lines.append(f"Multi-flow spans: {len(result.get('spans', []))}")
    lines.append(f"Cross-host spans: {result.get('cross_host_spans', 0)}")
    for span in result.get("spans", [])[:15]:
        tag = "CROSS-HOST" if span["cross_host"] else "same-host"
        lines.append(f"\n[{tag}] {span['id']}  ({span['count']} flows, hosts: {', '.join(span['hosts'])})")
        for e in span.get("entries", [])[:5]:
            lines.append(f"    {e.get('method', '')} {e['host']}{e['path']}")
    if not result.get("spans"):
        lines.append("\nNo shared correlation IDs across flows yet.")
    return "\n".join(lines)


def _ci(hdrs):
    return {k.lower(): v for k, v in (hdrs or {}).items()}
