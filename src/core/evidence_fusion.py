"""Evidence fusion — merge STATIC / LIVE / HEADERS / PROBES / TIMELINE into findings.

Findings are architecture conclusions (Gateway, CDN, Auth, …), not deduplicated strings.
Confidence is computed from independent evidence layers, not fixed WEAK labels.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, TYPE_CHECKING

from src.core.architecture_lexicon import LEXICON

if TYPE_CHECKING:
    from src.core.evidence_store import EvidenceItem, EvidenceStore

# Human titles for lexicon / extended finding keys
FINDING_TITLES: Dict[str, str] = {
    "service_mesh": "Envoy / Service Mesh Gateway",
    "gateway": "API Gateway",
    "rpc": "RPC / gRPC",
    "auth": "Authentication & Identity",
    "observability": "Observability / Tracing",
    "ml_inference": "ML / Inference Backend",
    "internal": "Staging / Internal / Debug Surface",
    "datastore": "Datastore",
    "messaging": "Messaging / Event Bus",
    "storage": "Object Storage",
    "orchestration": "Orchestration / Container Platform",
    "scheduling": "Job Scheduling / Queues",
    "cdn": "CDN / Edge Delivery",
    "streaming": "Streaming / SSE",
    "telemetry": "Client Telemetry",
    "feature_flags": "Feature Flags",
    "identity": "Tenant / Organization Identity",
    "direct_access": "Direct Server Access (Credential Replay)",
}

# Base score contributed when a layer is present (max one score per layer per finding)
LAYER_SCORE: Dict[str, int] = {
    "STATIC": 20,
    "LIVE": 40,
    "HEADERS": 60,
    "TIMELINE": 50,
    "FRIDA": 70,
    "PROBES": 85,
    "INFERENCE": 45,
}

# Response / request headers → finding key (substring match, lowercased)
HEADER_SIGNALS: List[tuple] = [
    ("x-envoy-upstream-service-time", "service_mesh"),
    ("x-envoy-", "service_mesh"),
    ("envoy", "service_mesh"),
    ("cf-ray", "cdn"),
    ("cf-cache-status", "cdn"),
    ("x-amz-cf-id", "cdn"),
    ("x-served-by", "cdn"),
    ("x-cache", "cdn"),
    ("via", "cdn"),
    ("fastly-", "cdn"),
    ("akamai-", "cdn"),
    ("traceparent", "observability"),
    ("x-trace-id", "observability"),
    ("x-correlation-id", "observability"),
    ("x-request-id", "observability"),
    ("server-timing", "gateway"),
    ("x-runtime", "gateway"),
    ("x-response-time", "gateway"),
    ("x-powered-by", "gateway"),
    ("anthropic-organization-id", "identity"),
    ("x-organization-id", "identity"),
    ("x-tenant-id", "identity"),
    ("authorization", "auth"),
    ("www-authenticate", "auth"),
    ("set-cookie", "auth"),
    ("anthropic-ratelimit", "gateway"),
    ("ratelimit-", "gateway"),
    ("x-ratelimit", "gateway"),
    ("content-type", "streaming"),  # handled specially for event-stream
]

FINDING_CONFOUNDERS: Dict[str, List[str]] = {
    "service_mesh": [
        "Header may be added by edge proxy, not origin service.",
        "Keyword in bundled library does not prove production mesh.",
    ],
    "gateway": [
        "Generic reverse-proxy headers are common on many stacks.",
    ],
    "cdn": [
        "CDN presence does not reveal origin architecture.",
    ],
    "internal": [
        "Static staging/debug strings may be dead code.",
        "No runtime confirmation without live call or probe.",
    ],
    "ml_inference": [
        "Client SDK references do not prove server-side model hosting.",
    ],
    "datastore": [
        "Error-message DB leaks not seen — do not infer datastore from static strings alone.",
    ],
    "auth": [
        "Auth headers observed on client requests — expected for any authenticated API.",
    ],
    "streaming": [
        "SSE/streaming is transport — not proof of a specific backend.",
    ],
    "direct_access": [
        "Replay uses the client's own captured credential — not a server vulnerability.",
    ],
}


@dataclass
class FusionEvidence:
    layer: str
    detail: str
    source: str = ""
    score: int = 0


@dataclass
class ArchitectureFinding:
    finding_key: str
    title: str
    evidence: List[FusionEvidence] = field(default_factory=list)
    score: int = 0
    confidence: str = "WEAK"
    reason: str = ""
    confounders: List[str] = field(default_factory=list)


def score_to_confidence(total: int) -> str:
    if total >= 86:
        return "OBSERVED"
    if total >= 61:
        return "STRONG"
    if total >= 31:
        return "MODERATE"
    return "WEAK"


def compute_finding_score(evidence: List[FusionEvidence]) -> int:
    """Sum the best score per layer (independent sources stack)."""
    by_layer: Dict[str, int] = {}
    for e in evidence:
        by_layer[e.layer] = max(by_layer.get(e.layer, 0), e.score or LAYER_SCORE.get(e.layer, 10))
    return min(100, sum(by_layer.values()))


def _item_text(item: "EvidenceItem") -> str:
    parts = [item.claim]
    for a in item.artifacts:
        parts.append(a.detail)
        if a.source:
            parts.append(a.source)
    return " ".join(parts).lower()


def _layer_for_item(item: "EvidenceItem") -> str:
    mod = (item.source_module or "").lower()
    tab = (item.source_tab or "").lower()
    if item.kind == "EXTRACTED":
        return "STATIC"
    if "probe" in mod or "controlled_probe" in mod:
        return "PROBES"
    if "frida" in mod or "runtime" in mod:
        return "FRIDA"
    if "timeline" in mod:
        return "TIMELINE"
    if "behavior_infer" in mod or item.kind == "INFERRED":
        return "INFERENCE"
    if item.level == "L3":
        return "PROBES"
    if item.level == "L2":
        return "LIVE"
    if "server_access" in mod or "access_path" in mod:
        return "PROBES"
    return "LIVE"


def classify_item(item: "EvidenceItem") -> Optional[str]:
    """Map an evidence atom to an architecture finding key."""
    text = _item_text(item)
    # Explicit category from lexicon (set by client_architecture_intel)
    cat = (item.category or "").lower()
    if cat in FINDING_TITLES and cat not in ("binary", "network", "access_path"):
        return cat
    if cat == "access_path":
        if "credential" in text or "direct server" in text:
            return "direct_access"
        return "internal"
    for finding_key, keywords in LEXICON.items():
        for kw in keywords:
            if kw.lower() in text:
                return finding_key
    if "staging" in text or "debug" in text or "feature flag" in text or "feature_flag" in text:
        return "internal"
    if "datadog" in text or "sentry" in text or "rum" in text:
        return "telemetry"
    if "event-stream" in text or "text/event-stream" in text or "sse" in text:
        return "streaming"
    if "cloudflare" in text or "cloudfront" in text or "cf-ray" in text:
        return "cdn"
    return None


def _merge_headers(flow: Dict[str, Any]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for hdr in (flow.get("req_headers") or {}, flow.get("resp_headers") or {}):
        for k, v in hdr.items():
            merged[k.lower()] = v
    return merged


def collect_header_evidence(flows: Sequence[Dict]) -> Dict[str, List[FusionEvidence]]:
    """Extract header-based evidence grouped by finding."""
    by_finding: Dict[str, List[FusionEvidence]] = defaultdict(list)
    seen: set = set()
    for f in flows or []:
        merged = _merge_headers(f)
        src = f"{f.get('method', 'GET')} {f.get('host', '')}{f.get('path', '')}"
        for hdr, val in merged.items():
            ct = val.lower() if hdr == "content-type" else ""
            if hdr == "content-type" and "event-stream" in ct:
                key = ("streaming", hdr, val[:40])
                if key not in seen:
                    seen.add(key)
                    by_finding["streaming"].append(FusionEvidence(
                        layer="HEADERS",
                        detail=f"content-type: {val[:80]}",
                        source=src,
                        score=LAYER_SCORE["HEADERS"],
                    ))
                continue
            for pattern, finding_key in HEADER_SIGNALS:
                if pattern == "content-type":
                    continue
                if pattern.endswith("-") and hdr.startswith(pattern):
                    match = True
                elif pattern in hdr:
                    match = True
                else:
                    match = False
                if not match:
                    continue
                dedup = (finding_key, hdr, val[:60])
                if dedup in seen:
                    break
                seen.add(dedup)
                orig = next((k for k in (f.get("resp_headers") or {}) if k.lower() == hdr), hdr)
                by_finding[finding_key].append(FusionEvidence(
                    layer="HEADERS",
                    detail=f"{orig}: {str(val)[:120]}",
                    source=src,
                    score=LAYER_SCORE["HEADERS"],
                ))
                break
    return by_finding


def collect_live_evidence(flows: Sequence[Dict]) -> Dict[str, List[FusionEvidence]]:
    """Live traffic observations (hosts, paths) by finding."""
    by_finding: Dict[str, List[FusionEvidence]] = defaultdict(list)
    for f in flows or []:
        blob = f"{f.get('host','')} {f.get('path','')} {f.get('url','')}".lower()
        src = f"{f.get('method', 'GET')} {f.get('host', '')}{f.get('path', '')} HTTP {f.get('status', '')}"
        for finding_key, keywords in LEXICON.items():
            if any(kw in blob for kw in keywords):
                by_finding[finding_key].append(FusionEvidence(
                    layer="LIVE",
                    detail=f"Live call observed",
                    source=src,
                    score=LAYER_SCORE["LIVE"],
                ))
        if "staging" in blob or "internal" in blob or "/debug" in blob:
            by_finding["internal"].append(FusionEvidence(
                layer="LIVE",
                detail="Live call to staging/debug path",
                source=src,
                score=LAYER_SCORE["LIVE"],
            ))
    return by_finding


def collect_probe_evidence(probe_results: Sequence[Dict]) -> Dict[str, List[FusionEvidence]]:
    by_finding: Dict[str, List[FusionEvidence]] = defaultdict(list)
    for pr in probe_results or []:
        if pr.get("skipped"):
            continue
        resp = pr.get("response") or {}
        status = resp.get("status", 0)
        body = (resp.get("body") or "")[:200]
        url = pr.get("url", "")
        detail = f"Probe [{pr.get('template')}] HTTP {status}"
        if body:
            detail += f" — {body[:100]}"
        # JSON error response = gateway/API behavior
        by_finding["gateway"].append(FusionEvidence(
            layer="PROBES",
            detail=detail,
            source=url,
            score=LAYER_SCORE["PROBES"],
        ))
        if status in (401, 403):
            by_finding["auth"].append(FusionEvidence(
                layer="PROBES",
                detail=f"Auth gate confirmed (HTTP {status})",
                source=url,
                score=LAYER_SCORE["PROBES"],
            ))
    return by_finding


def collect_static_from_items(items: Sequence["EvidenceItem"]) -> Dict[str, List[FusionEvidence]]:
    by_finding: Dict[str, List[FusionEvidence]] = defaultdict(list)
    for item in items:
        if item.kind != "EXTRACTED" and _layer_for_item(item) != "STATIC":
            continue
        key = classify_item(item)
        if not key:
            continue
        detail = item.claim
        if item.artifacts:
            detail = item.artifacts[0].detail or item.claim
        src = item.source_tab or item.source_module or "static"
        by_finding[key].append(FusionEvidence(
            layer="STATIC",
            detail=detail[:200],
            source=src,
            score=LAYER_SCORE["STATIC"],
        ))
    return by_finding


def collect_other_items(items: Sequence["EvidenceItem"]) -> Dict[str, List[FusionEvidence]]:
    """Non-static store items (inference, access, measured)."""
    by_finding: Dict[str, List[FusionEvidence]] = defaultdict(list)
    for item in items:
        if item.kind == "EXTRACTED":
            continue
        key = classify_item(item)
        if not key:
            continue
        layer = _layer_for_item(item)
        detail = item.claim
        if item.artifacts:
            detail = f"{item.claim} — {item.artifacts[0].detail[:120]}"
        by_finding[key].append(FusionEvidence(
            layer=layer,
            detail=detail[:220],
            source=item.source_tab or item.source_module,
            score=LAYER_SCORE.get(layer, 30),
        ))
    return by_finding


def _dedupe_evidence(evidences: List[FusionEvidence]) -> List[FusionEvidence]:
    seen = set()
    out = []
    for e in evidences:
        key = (e.layer, e.detail[:80], e.source[:60])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _build_reason(key: str, evidence: List[FusionEvidence], score: int) -> str:
    layers = sorted({e.layer for e in evidence})
    if len(layers) == 1 and layers[0] == "STATIC":
        return "Only static evidence — no runtime confirmation yet."
    if "PROBES" in layers and "HEADERS" in layers:
        return "Static signal corroborated by live headers and controlled probe response."
    if "HEADERS" in layers and "STATIC" in layers:
        return "Binary/source keyword aligned with live response headers."
    if "LIVE" in layers and "STATIC" in layers:
        return "Static indicator confirmed by observed live traffic."
    if "PROBES" in layers:
        return "Controlled probe received structured server response."
    if score >= 61:
        return "Multiple independent evidence layers converge on this finding."
    return "Limited evidence — treat as hypothesis."


def fuse(*, store: "EvidenceStore", flows: Optional[Sequence[Dict]] = None,
         probe_results: Optional[Sequence[Dict]] = None) -> List[ArchitectureFinding]:
    """Produce architecture findings from all evidence sources."""
    items = store.all_items()
    buckets: Dict[str, List[FusionEvidence]] = defaultdict(list)

    for src in (
        collect_static_from_items(items),
        collect_other_items(items),
        collect_header_evidence(flows or []),
        collect_live_evidence(flows or []),
        collect_probe_evidence(probe_results or []),
    ):
        for key, evs in src.items():
            buckets[key].extend(evs)

    findings: List[ArchitectureFinding] = []
    for key, evs in buckets.items():
        evs = _dedupe_evidence(evs)
        if not evs:
            continue
        total = compute_finding_score(evs)
        conf = score_to_confidence(total)
        findings.append(ArchitectureFinding(
            finding_key=key,
            title=FINDING_TITLES.get(key, key.replace("_", " ").title()),
            evidence=sorted(evs, key=lambda e: (-e.score, e.layer)),
            score=total,
            confidence=conf,
            reason=_build_reason(key, evs, total),
            confounders=list(FINDING_CONFOUNDERS.get(key, [])),
        ))

    findings.sort(key=lambda f: (-f.score, f.title))
    return findings


def format_fusion_report(findings: Sequence[ArchitectureFinding]) -> str:
    if not findings:
        return ("FUSION FINDINGS\n" + "=" * 60 + "\n"
                "No architecture findings yet — run analysis, capture traffic, and probe.")
    lines = ["FUSION FINDINGS", "=" * 60,
             "Architecture conclusions fused from STATIC + LIVE + HEADERS + PROBES + …",
             ""]
    for f in findings:
        lines.append(f"Finding: {f.title}")
        lines.append(f"Confidence: {f.confidence}  (score {f.score}/100)")
        lines.append(f"Reason: {f.reason}")
        lines.append("Evidence:")
        by_layer: Dict[str, List[FusionEvidence]] = defaultdict(list)
        for e in f.evidence:
            by_layer[e.layer].append(e)
        for layer in ("STATIC", "LIVE", "HEADERS", "TIMELINE", "FRIDA", "PROBES", "INFERENCE"):
            if layer not in by_layer:
                continue
            lines.append(f"  [{layer}]")
            for e in by_layer[layer][:8]:
                src = f"  ({e.source})" if e.source else ""
                lines.append(f"    • {e.detail}{src}")
            extra = len(by_layer[layer]) - 8
            if extra > 0:
                lines.append(f"    … +{extra} more")
        if f.finding_key == "internal":
            if "LIVE" not in by_layer:
                lines.append("  [LIVE]")
                lines.append("    (no runtime access)")
            if "PROBES" not in by_layer:
                lines.append("  [PROBES]")
                lines.append("    none")
        if f.confounders:
            lines.append("Confounders:")
            for c in f.confounders[:4]:
                lines.append(f"  • {c}")
        lines.append("")
    return "\n".join(lines)

def ingest_probe_result(store: "EvidenceStore", result: Dict):
    """Record a probe outcome as evidence for fusion."""
    if result.get("skipped"):
        return
    from src.core.evidence_store import L3, MEASURED, CONF_MODERATE
    resp = result.get("response") or {}
    store.add_simple(
        claim=f"Controlled probe [{result.get('template')}] HTTP {resp.get('status', 0)}",
        level=L3,
        kind=MEASURED,
        category="gateway",
        confidence=CONF_MODERATE,
        detail=(resp.get("body") or "")[:200],
        source=result.get("url", ""),
        source_tab="Access Path",
        source_module="controlled_probe",
    )
