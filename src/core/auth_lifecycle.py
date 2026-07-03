"""Auth lifecycle mapping — login → token → refresh → org scope."""

import re
from typing import Dict, List, Any, Optional

_AUTH_PATHS = re.compile(r"/(?:auth|login|oauth|token|refresh|session|signin|signup)", re.I)
_BEARER = re.compile(r"[Bb]earer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")
_ORG_HDR = re.compile(r"(?:org(?:anization)?[-_]?(?:id|slug)|x-org)", re.I)


def analyze_flows(flows: List[Dict]) -> Dict[str, Any]:
    """Extract auth lifecycle events from captured flows."""
    events = []
    tokens_seen = []
    org_ids = set()

    for f in flows or []:
        path = f.get("path", "") or ""
        method = (f.get("method") or "").upper()
        status = str(f.get("status", ""))
        ts = f.get("ts", 0)

        if _AUTH_PATHS.search(path):
            events.append({
                "type": "auth_endpoint",
                "ts": ts, "method": method, "path": path, "status": status,
                "host": f.get("host", ""),
            })

        # Request Authorization header
        req_h = _ci(f.get("req_headers") or {})
        auth = req_h.get("authorization", "")
        if auth:
            m = _BEARER.search(auth)
            if m:
                prefix = m.group(1)[:20] + "…"
                if prefix not in tokens_seen:
                    tokens_seen.append(prefix)
                events.append({
                    "type": "bearer_token_used",
                    "ts": ts, "path": path, "token_prefix": prefix,
                })

        # Set-Cookie on login responses
        resp_h = _ci(f.get("resp_headers") or {})
        if "set-cookie" in resp_h and status.startswith("2"):
            if _AUTH_PATHS.search(path):
                events.append({
                    "type": "session_cookie_set",
                    "ts": ts, "path": path,
                    "cookie": resp_h["set-cookie"][:80],
                })

        for hk, hv in resp_h.items():
            if _ORG_HDR.search(hk):
                org_ids.add(f"{hk}: {hv}")

    events.sort(key=lambda e: e.get("ts", 0))
    return {
        "events": events,
        "token_count": len(tokens_seen),
        "org_scoping": sorted(org_ids),
        "has_login": any(e["type"] == "auth_endpoint" for e in events),
        "has_bearer": any(e["type"] == "bearer_token_used" for e in events),
    }


def format_report(analysis: Dict[str, Any]) -> str:
    if not analysis.get("events"):
        return "No auth lifecycle events captured yet."
    lines = ["AUTH LIFECYCLE", "=" * 60]
    lines.append(f"Login endpoints seen: {'yes' if analysis.get('has_login') else 'no'}")
    lines.append(f"Bearer tokens used: {analysis.get('token_count', 0)}")
    if analysis.get("org_scoping"):
        lines.append(f"Org scoping headers: {', '.join(analysis['org_scoping'][:5])}")
    lines.append("\nTimeline:")
    for e in analysis["events"][:30]:
        lines.append(f"  [{e['type']}] {e.get('method', '')} {e.get('path', e.get('token_prefix', ''))} "
                     f"→ {e.get('status', '')}")
    return "\n".join(lines)


def _ci(hdrs):
    return {k.lower(): v for k, v in (hdrs or {}).items()}
