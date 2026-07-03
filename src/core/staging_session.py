"""Staging session — client-provided authenticated access."""

import os
from typing import Dict, List, Any, Set, Optional

from src.core.engagement_scope import engagement_manager


def load_credential(ref: str) -> str:
    """Resolve credential from scope ref (env:VAR_NAME). Never read from repo files."""
    if not ref:
        return ""
    if ref.startswith("env:"):
        return os.environ.get(ref[4:], "")
    return ""


def diff_api_surfaces(anonymous_flows: List[Dict], authenticated_flows: List[Dict]) -> Dict:
    """Compare endpoints visible with vs without auth."""
    def surface(flows):
        s = set()
        for f in flows or []:
            s.add((f.get("host", ""), f.get("method", ""), f.get("path", "")))
        return s

    anon = surface(anonymous_flows)
    auth = surface(authenticated_flows)
    return {
        "anonymous_only": sorted(anon - auth),
        "authenticated_only": sorted(auth - anon),
        "shared": sorted(anon & auth),
        "auth_exclusive_count": len(auth - anon),
    }


def format_post_auth_report(diff: Dict) -> str:
    lines = ["POST-AUTH RECON", "=" * 60]
    lines.append(f"Endpoints only with auth: {diff.get('auth_exclusive_count', 0)}")
    for item in diff.get("authenticated_only", [])[:20]:
        lines.append(f"  + {item[1]} {item[0]}{item[2]}")
    lines.append(f"\nShared endpoints: {len(diff.get('shared', []))}")
    return "\n".join(lines)


def start_staging_session() -> Dict:
    mgr = engagement_manager()
    allowed, reason = mgr.scope.check(action="staging_access")
    if not allowed:
        return {"ok": False, "reason": reason}
    cred_ref = mgr.scope.staging_credentials_ref
    cred = load_credential(cred_ref)
    mgr.log("staging_session", "start", "ok" if cred else "no_cred")
    return {
        "ok": True,
        "has_credential": bool(cred),
        "client": mgr.scope.client,
    }
