"""Access Path Engine — discover and surface server entry candidates."""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

_ADMIN_PATH = re.compile(r"/(?:admin|debug|internal|status|health|metrics|__debug)", re.I)
_STAGING_HOST = re.compile(r"(?:staging|dev|test|internal|localhost)", re.I)


@dataclass
class AccessPathCandidate:
    path_type: str       # credential | admin_endpoint | debug_flag | staging_host | auth_bypass_hint
    label: str
    detail: str
    confidence: str = "WEAK"
    validation_status: str = "untested"   # untested | confirmed_works | rejected
    source: str = ""
    artifacts: List[str] = field(default_factory=list)


def discover(*, vuln_findings=None, architecture_intel=None, captured_secrets=None,
             flows=None, app_name="") -> List[AccessPathCandidate]:
    """Surface access path candidates from RE + capture."""
    candidates = []
    seen = set()

    # Secrets from vuln audit
    for f in vuln_findings or []:
        cat = getattr(f, "category", f.get("category", "")) if f else ""
        val = getattr(f, "value", f.get("value", "")) if f else ""
        if not val:
            continue
        key = ("credential", val[:30])
        if key in seen:
            continue
        seen.add(key)
        candidates.append(AccessPathCandidate(
            path_type="credential",
            label=f"Extracted secret: {cat}",
            detail=val[:120] + ("…" if len(val) > 120 else ""),
            confidence="MODERATE",
            source="vuln_audit",
            artifacts=[val[:40] + "…"],
        ))

    # Captured network secrets
    for s in captured_secrets or []:
        val = s if isinstance(s, str) else s.get("value", "")
        if not val:
            continue
        key = ("credential", val[:30])
        if key in seen:
            continue
        seen.add(key)
        candidates.append(AccessPathCandidate(
            path_type="credential",
            label="Captured traffic secret",
            detail=val[:80],
            confidence="STRONG",
            source="network_capture",
        ))

    intel = architecture_intel or {}
    for flag in intel.get("feature_flags", []):
        name = flag.get("name", "") if isinstance(flag, dict) else str(flag)
        candidates.append(AccessPathCandidate(
            path_type="debug_flag",
            label=f"Feature flag: {name}",
            detail=flag.get("file", "") if isinstance(flag, dict) else "",
            confidence="WEAK",
            source="client_architecture_intel",
        ))

    for ep in intel.get("endpoints", []):
        if _ADMIN_PATH.search(ep):
            candidates.append(AccessPathCandidate(
                path_type="admin_endpoint",
                label=f"Admin/debug path: {ep}",
                detail=ep,
                confidence="MODERATE",
                source="static_analysis",
            ))

    for host in intel.get("hosts", []):
        if _STAGING_HOST.search(host):
            candidates.append(AccessPathCandidate(
                path_type="staging_host",
                label=f"Staging/internal host: {host}",
                detail=host,
                confidence="MODERATE",
                source="static_analysis",
            ))

    # Live flows — primary API endpoint (auto-detected probe base)
    if flows:
        try:
            from src.core import api_base_url as abu
            sugg = abu.suggest(flows=flows, app_name=app_name or (intel or {}).get("path", ""))
            if sugg and sugg.url:
                candidates.insert(0, AccessPathCandidate(
                    path_type="live_api",
                    label="Auto-detected API base (from capture)",
                    detail=sugg.url,
                    confidence="STRONG",
                    validation_status="confirmed_works",
                    source="network_capture",
                    artifacts=[sugg.reason],
                ))
        except Exception:
            pass

    # Live flows — admin paths seen
    for f in flows or []:
        path = f.get("path", "")
        if _ADMIN_PATH.search(path):
            key = ("admin_endpoint", path)
            if key not in seen:
                seen.add(key)
                candidates.append(AccessPathCandidate(
                    path_type="admin_endpoint",
                    label=f"Live admin path: {path}",
                    detail=f"{f.get('host', '')}{path} HTTP {f.get('status', '')}",
                    confidence="STRONG",
                    source="network_capture",
                ))

    return candidates


def format_report(candidates: List[AccessPathCandidate]) -> str:
    lines = ["ACCESS PATH CANDIDATES", "=" * 60]
    lines.append("Discovered entry points from binary analysis and captured traffic.")
    lines.append("Base URL above is auto-filled — Validate or Run Controlled Probe.\n")
    if not candidates:
        return lines[0] + "\n" + "=" * 60 + "\nNo candidates yet."
    by_type = {}
    for c in candidates:
        by_type.setdefault(c.path_type, []).append(c)
    for ptype, items in sorted(by_type.items()):
        lines.append(f"\n## {ptype.replace('_', ' ').title()} ({len(items)})")
        for c in items[:15]:
            status = c.validation_status
            lines.append(f"  [{c.confidence}/{status}] {c.label}")
            lines.append(f"      {c.detail[:100]}")
    return "\n".join(lines)
