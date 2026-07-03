"""BLUE TEAM hardening recommendations from RED TEAM evidence."""

from typing import Dict, List, Any

from src.core.evidence_store import session_store, L3, INFERRED, CONF_STRONG


HARDENING_MAP = {
    "credential": "Rotate exposed credentials; move to secure vault; never embed in client binary.",
    "admin_endpoint": "Remove or restrict admin/debug endpoints from production; require auth + IP allowlist.",
    "debug_flag": "Disable debug feature flags in production builds.",
    "binary": "Remove architecture keywords and internal hostnames from shipped binaries.",
    "network": "Strip internal headers (x-envoy-*, Server-Timing) at edge before client.",
    "probe": "Sanitize error responses; disable stack traces in production.",
    "access_path": "Validate all discovered access paths; enforce least-privilege staging isolation.",
}


def recommendations_from_evidence() -> List[Dict[str, str]]:
    store = session_store()
    recs = []
    seen = set()
    for item in store.all_items():
        cat = item.category
        key = (cat, item.claim[:60])
        if key in seen:
            continue
        seen.add(key)
        action = HARDENING_MAP.get(cat, HARDENING_MAP.get("network", ""))
        if item.confidence in (CONF_STRONG, "STRONG") or item.level == L3:
            priority = "HIGH"
        else:
            priority = "MEDIUM"
        recs.append({
            "finding": item.claim,
            "category": cat,
            "priority": priority,
            "recommendation": action,
            "confidence": item.confidence,
        })
    recs.sort(key=lambda r: (0 if r["priority"] == "HIGH" else 1, r["category"]))
    return recs


def format_report(recs: List[Dict]) -> str:
    lines = ["BLUE TEAM — HARDENING RECOMMENDATIONS", "=" * 60]
    lines.append("Derived from RED TEAM evidence collected in this engagement.\n")
    if not recs:
        return lines[0] + "\n" + "=" * 60 + "\nNo evidence yet — run analysis first."
    for r in recs[:40]:
        lines.append(f"[{r['priority']}] {r['finding']}")
        lines.append(f"    → {r['recommendation']}\n")
    return "\n".join(lines)
