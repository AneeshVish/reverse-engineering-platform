"""Personal / identifying data detection in captured request payloads (claim 2).

The honest version of "the app sends all your data": we don't claim "all" — we scan
the ACTUAL request bodies captured live and flag the specific personal/identifying
fields being transmitted (email, advertising/device IDs, location, auth tokens,
phone, etc.). "We captured device_id + advertising_id POSTed to app-measurement.com"
is undeniable; "they send everything" is not.

Heuristic and offline. Returns located, labelled hits with a short redacted sample.
"""

import re

# (label, severity, compiled pattern). Patterns run over the raw body bytes.
_PATTERNS = [
    ("Email address", "high",
     re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("UUID / advertising-style ID", "high",
     re.compile(rb"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("Device/ad identifier field", "high",
     re.compile(rb"\"(?:device[_-]?id|deviceid|udid|idfa|idfv|gaid|android[_-]?id|"
                rb"advertising[_-]?id|ad[_-]?id|client[_-]?id|installation[_-]?id)\"", re.I)),
    ("Auth token / session", "critical",
     re.compile(rb"\"(?:access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|"
                rb"bearer|session[_-]?id|sessionid|api[_-]?key)\"\s*[:=]", re.I)),
    ("GPS / location", "high",
     re.compile(rb"\"(?:lat|latitude|lon|lng|longitude|gps|geo|coords?)\"\s*[:=]\s*-?\d{1,3}\.\d+",
                re.I)),
    ("Phone number", "high",
     re.compile(rb"\+\d{10,15}\b")),
    ("IMEI", "high", re.compile(rb"\bimei\"?\s*[:=]\s*\"?\d{15}\b", re.I)),
    ("Credit-card-like number", "critical",
     re.compile(rb"\b(?:\d[ -]?){13,16}\b")),
    ("Username / account field", "medium",
     re.compile(rb"\"(?:username|user[_-]?name|login|account[_-]?id|user[_-]?id)\"\s*[:=]", re.I)),
]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _redact(sample):
    s = sample.decode("latin-1", "replace")
    if len(s) <= 12:
        return s
    return s[:6] + "…" + s[-3:]


def find_pii(body):
    """Scan a request body (bytes or str) and return [(label, severity, sample)]."""
    if body is None:
        return []
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    seen = set()
    hits = []
    for label, severity, pat in _PATTERNS:
        m = pat.search(body)
        if not m:
            continue
        key = (label,)
        if key in seen:
            continue
        seen.add(key)
        hits.append((label, severity, _redact(m.group(0))))
    hits.sort(key=lambda h: _SEV_RANK.get(h[1], 9))
    return hits


def classify_request(method, url, body):
    """Summarize the PII in one captured request."""
    hits = find_pii(body)
    return {"method": method, "url": url, "pii": hits, "pii_count": len(hits)}


def format_request_pii(req):
    if not req.get("pii"):
        return ""
    head = f"{req.get('method', '')} {req.get('url', '')}".strip()
    lines = [f"  {head}"]
    for label, severity, sample in req["pii"]:
        lines.append(f"      [{severity.upper()}] {label}: {sample}")
    return "\n".join(lines)
