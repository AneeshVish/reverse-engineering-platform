"""Access path validation — scope-gated replay and probe actions."""

import json
import time
from typing import Dict, Any

from src.core.engagement_scope import engagement_manager
from src.core.access_path_engine import AccessPathCandidate
from src.core.https_client import http_request


def replay_credential(url: str, credential: str, method: str = "GET") -> Dict:
    mgr = engagement_manager()
    from urllib.parse import urlparse
    p = urlparse(url)
    allowed, reason = mgr.scope.check(
        action="credential_replay", host=p.hostname or "", path=p.path or "/")
    if not allowed:
        return {"action": "replay_credential", "skipped": True, "reason": reason}
    headers = {"Authorization": credential if credential.startswith("Bearer") else f"Bearer {credential}"}
    resp = http_request(url, method=method, headers=headers, timeout=15)
    if resp.get("error"):
        result = {"status": 0, "error": resp["error"]}
    else:
        result = {"status": resp["status"], "body_preview": resp.get("body", "")[:500]}
    mgr.log("credential_replay", url, str(result.get("status", "err")))
    return {"action": "replay_credential", "url": url, "result": result}


def probe_admin_path(base_url: str, path: str, auth_header: str = "") -> Dict:
    mgr = engagement_manager()
    from urllib.parse import urljoin, urlparse
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    p = urlparse(url)
    allowed, reason = mgr.scope.check(
        action="controlled_probe", host=p.hostname or "", path=p.path or "/")
    if not allowed:
        return {"action": "probe_admin_path", "skipped": True, "reason": reason}
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    resp = http_request(url, method="GET", headers=headers, timeout=15)
    if resp.get("error"):
        result = {"status": 0, "error": resp["error"]}
    else:
        result = {"status": resp["status"], "body_preview": resp.get("body", "")[:500]}
    mgr.log("probe_admin_path", url, str(result.get("status", "err")))
    return {"action": "probe_admin_path", "url": url, "result": result}


def validate_candidate(candidate: AccessPathCandidate, base_url: str = "",
                       auth_header: str = "") -> AccessPathCandidate:
    if candidate.path_type == "admin_endpoint" and base_url:
        r = probe_admin_path(base_url, candidate.detail, auth_header)
        if not r.get("skipped"):
            status = r.get("result", {}).get("status", 0)
            if status and int(status) < 400:
                candidate.validation_status = "confirmed_works"
            elif status in (401, 403):
                candidate.validation_status = "rejected"
            else:
                candidate.validation_status = "untested"
    elif candidate.path_type == "credential" and base_url and candidate.artifacts:
        cred = candidate.artifacts[0]
        r = replay_credential(base_url, cred)
        if not r.get("skipped"):
            status = r.get("result", {}).get("status", 0)
            candidate.validation_status = "confirmed_works" if status and int(status) < 400 else "rejected"
    return candidate


def check_base_url(url: str) -> Dict[str, Any]:
    """Quick reachability check for the auto-detected probe base URL."""
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or "/"
    mgr = engagement_manager()
    allowed, reason = mgr.scope.check(action="controlled_probe", host=host, path=path)
    if not allowed:
        return {"url": url, "skipped": True, "reason": reason}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    resp = http_request(url, method="POST", headers=headers,
                        body=b'{"probe":true}', timeout=12)
    if resp.get("error"):
        return {"url": url, "status": 0, "error": resp["error"], "skipped": False}
    return {
        "url": url,
        "status": resp["status"],
        "body_preview": resp.get("body", "")[:400],
        "skipped": False,
    }


def format_base_check(result: Dict[str, Any]) -> str:
    lines = ["BASE URL CHECK", "-" * 40]
    if result.get("skipped"):
        lines.append(f"Skipped: {result.get('reason', '')}")
        return "\n".join(lines)
    status = result.get("status", 0)
    lines.append(f"URL: {result.get('url', '')}")
    lines.append(f"HTTP {status}")
    if status in (401, 403):
        lines.append("Reachable — auth required (expected for API probes).")
    elif status == 404:
        lines.append("Host reachable but path not found — re-capture or wait for auto-detect.")
    elif 200 <= status < 300:
        lines.append("Endpoint accepted the request.")
    elif status >= 400:
        lines.append("Server responded — suitable for controlled error probes.")
    if result.get("body_preview"):
        lines.append(f"Body: {result['body_preview'][:200]}")
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    return "\n".join(lines)
