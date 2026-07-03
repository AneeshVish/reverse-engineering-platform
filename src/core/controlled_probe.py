"""Controlled error probes — scope-gated, rate-limited."""

import json
import time
from typing import Dict, List, Any, Optional

from src.core.engagement_scope import engagement_manager
from src.core.https_client import http_request

# Probe templates: (name, description, mutate_fn)
MAX_PROBES_PER_SESSION = 20
_probe_count = 0


def _check_scope(action: str, host: str, path: str) -> tuple:
    return engagement_manager().scope.check(action=action, host=host, path=path)


def _http_probe(url: str, method: str = "POST", headers: Dict = None,
                body: bytes = b"", timeout: float = 10.0) -> Dict:
    return http_request(url, method=method, headers=headers, body=body or None, timeout=timeout)


def run_probe(template: str, base_url: str, auth_header: str = "",
              extra: Dict = None) -> Dict:
    """Run a single controlled probe. Returns result dict."""
    global _probe_count
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    path = parsed.path or "/"

    allowed, reason = _check_scope("controlled_probe", host, path)
    if not allowed:
        return {"template": template, "skipped": True, "reason": reason}

    if _probe_count >= MAX_PROBES_PER_SESSION:
        return {"template": template, "skipped": True,
                "reason": f"Probe cap ({MAX_PROBES_PER_SESSION}) reached."}

    _probe_count += 1
    mgr = engagement_manager()
    headers = {"Content-Type": "application/json", "User-Agent": "RE-Platform-Probe/1.0"}
    if auth_header:
        headers["Authorization"] = auth_header

    result = {"template": template, "url": base_url, "ts": time.time()}

    if template == "invalid_json":
        result["response"] = _http_probe(base_url, "POST", headers, b"{not valid json")
    elif template == "invalid_id":
        url = base_url.replace("CONV_ID", "00000000-0000-0000-0000-000000000000")
        result["response"] = _http_probe(url, "POST", headers,
                                         json.dumps({"message_content": "probe"}).encode())
    elif template == "oversized_body":
        big = json.dumps({"message_content": "x" * 100000}).encode()
        result["response"] = _http_probe(base_url, "POST", headers, big)
    elif template == "wrong_content_type":
        headers["Content-Type"] = "text/plain"
        result["response"] = _http_probe(base_url, "POST", headers, b"plain text probe")
    elif template == "missing_auth":
        headers.pop("Authorization", None)
        result["response"] = _http_probe(base_url, "POST", headers,
                                         json.dumps({}).encode())
    elif template == "expired_session":
        headers["Authorization"] = "Bearer expired.invalid.token"
        result["response"] = _http_probe(base_url, "POST", headers,
                                         json.dumps({}).encode())
    else:
        result["skipped"] = True
        result["reason"] = f"Unknown template: {template}"

    mgr.log("controlled_probe", base_url, str(result.get("response", {}).get("status", "skip")),
            template)
    return result


PROBE_TEMPLATES = [
    ("invalid_json", "Send malformed JSON body"),
    ("invalid_id", "Use invalid resource/conversation ID"),
    ("oversized_body", "Send oversized payload"),
    ("wrong_content_type", "Wrong Content-Type header"),
    ("missing_auth", "Request without Authorization"),
    ("expired_session", "Request with invalid/expired token"),
]


def analyze_leaks(probe_results: List[Dict]) -> List[Dict]:
    """Detect implementation leaks in probe responses."""
    from src.core import behavior_infer as bi
    leaks = []
    for pr in probe_results:
        resp = pr.get("response") or {}
        body = resp.get("body", "")
        if not body:
            continue
        # Reuse behavior_infer DB error signatures
        for pattern, engine in bi._DB_ERROR_SIGS:
            import re
            if re.search(pattern, body):
                leaks.append({
                    "template": pr.get("template"),
                    "leak_type": "database_error",
                    "engine": engine,
                    "snippet": body[:200],
                })
                break
        for marker in ("Traceback", "stack trace", "Exception", "at line",
                       "SyntaxError", "Internal Server Error"):
            if marker.lower() in body.lower():
                leaks.append({
                    "template": pr.get("template"),
                    "leak_type": "stack_trace",
                    "snippet": body[:200],
                })
                break
    return leaks


def format_report(results: List[Dict], leaks: List[Dict]) -> str:
    lines = ["ACTIVE PROBES (controlled error injection)", "=" * 60]
    if not results:
        return lines[0] + "\n" + "=" * 60 + "\nNo probes run. Load scope + select templates."
    for r in results:
        if r.get("skipped"):
            lines.append(f"\n[{r.get('template')}] SKIPPED: {r.get('reason')}")
            continue
        resp = r.get("response", {})
        lines.append(f"\n[{r.get('template')}] HTTP {resp.get('status')} — {r.get('url', '')[:60]}")
        if resp.get("error"):
            lines.append(f"    error: {resp['error'][:160]}")
        elif resp.get("body"):
            lines.append(f"    body: {resp['body'][:120]}…")
    if leaks:
        lines.append(f"\nLEAKS DETECTED ({len(leaks)}):")
        for lk in leaks:
            lines.append(f"  • [{lk.get('leak_type')}] {lk.get('engine', '')} from {lk.get('template')}")
    return "\n".join(lines)
