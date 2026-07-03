"""Tests for evidence fusion engine."""

from src.core.evidence_store import (
    EvidenceStore, EvidenceItem, EvidenceArtifact, L1, L2, EXTRACTED, CONF_WEAK,
)
from src.core import evidence_fusion as ef


def _static_envoy(store):
    store.add(EvidenceItem(
        claim="Binary/source references 'envoy' (service_mesh)",
        level=L1, kind=EXTRACTED, category="service_mesh",
        artifacts=[EvidenceArtifact(detail="keyword: envoy", source="binary")],
    ))


def test_fusion_envoy_static_plus_headers():
    store = EvidenceStore()
    _static_envoy(store)
    flows = [{
        "method": "POST",
        "host": "api.example.com",
        "path": "/v1/messages",
        "status": 401,
        "resp_headers": {"x-envoy-upstream-service-time": "42"},
    }]
    findings = ef.fuse(store=store, flows=flows)
    mesh = next((f for f in findings if f.finding_key == "service_mesh"), None)
    assert mesh is not None
    assert mesh.score >= 61
    assert mesh.confidence in ("STRONG", "OBSERVED")
    layers = {e.layer for e in mesh.evidence}
    assert "STATIC" in layers
    assert "HEADERS" in layers
    report = ef.format_fusion_report(findings)
    assert "Envoy" in report
    assert "HEADERS" in report


def test_fusion_staging_static_only_weak():
    store = EvidenceStore()
    store.add(EvidenceItem(
        claim="Binary/source references 'staging' (internal)",
        level=L1, kind=EXTRACTED, category="internal",
        artifacts=[EvidenceArtifact(detail="keyword: staging", source="binary")],
    ))
    findings = ef.fuse(store=store, flows=[])
    internal = next((f for f in findings if f.finding_key == "internal"), None)
    assert internal is not None
    assert internal.confidence == "WEAK"
    assert "static" in internal.reason.lower()
    report = ef.format_fusion_report(findings)
    assert "(no runtime access)" in report


def test_fusion_probe_adds_gateway_and_auth():
    store = EvidenceStore()
    probes = [{
        "template": "api_root",
        "url": "https://api.example.com/v1/messages",
        "response": {"status": 401, "body": '{"error":"x-api-key required"}'},
    }]
    findings = ef.fuse(store=store, probe_results=probes)
    auth = next((f for f in findings if f.finding_key == "auth"), None)
    assert auth is not None
    assert any(e.layer == "PROBES" for e in auth.evidence)


def test_score_to_confidence():
    assert ef.score_to_confidence(20) == "WEAK"
    assert ef.score_to_confidence(31) == "MODERATE"
    assert ef.score_to_confidence(61) == "STRONG"
    assert ef.score_to_confidence(86) == "OBSERVED"


def test_store_format_report_leads_with_fusion():
    store = EvidenceStore()
    _static_envoy(store)
    text = store.format_report(flows=[], probe_results=[], include_raw=True)
    assert text.startswith("FUSION FINDINGS")
    assert "RAW EVIDENCE ATOMS" in text
