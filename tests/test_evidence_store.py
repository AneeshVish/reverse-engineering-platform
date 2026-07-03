"""Tests for EvidenceStore and engagement scope."""

from src.core.evidence_store import (
    EvidenceStore, EvidenceItem, EvidenceArtifact, L1, L2, EXTRACTED, CONF_WEAK,
    session_store, reset_session_store,
)
from src.core.engagement_scope import EngagementScope, engagement_manager, ROE_CHECKLIST
from src.core.target_profile import TargetProfile, session_profile, set_session_profile


def test_evidence_store_add_and_fuse():
    store = EvidenceStore()
    a = store.add(EvidenceItem(claim="Static endpoint /v1/messages", level=L1,
                               kind=EXTRACTED, category="binary"))
    b = store.add(EvidenceItem(claim="Live call to /v1/messages", level=L2,
                               category="network"))
    store.link(a.id, b.id)
    groups = store.fused_groups()
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_engagement_scope_gates_actions(monkeypatch):
    import src.core.engagement_scope as es
    monkeypatch.setattr(es, "SCOPE_GATE_ENABLED", True)
    scope = EngagementScope(client="TestCo", scope_hosts=["api.example.com"],
                            roe_acknowledged=True,
                            allowed_actions=["passive_capture", "controlled_probe"])
    ok, _ = scope.check(action="controlled_probe", host="api.example.com", path="/v1/x")
    assert ok
    ok, reason = scope.check(action="controlled_probe", host="evil.com", path="/")
    assert not ok
    ok, _ = scope.check(action="credential_replay", host="api.example.com")
    assert not ok  # not in allowed_actions


def test_roe_checklist_nonempty():
    assert len(ROE_CHECKLIST) >= 5


def test_target_profile_merge():
    p = TargetProfile.from_path("/tmp/Claude.app")
    assert p.kind == "app"
    p.merge_architecture_intel({"endpoints": ["/v1/messages"], "hosts": ["api.anthropic.com"],
                                "hits": [], "feature_flags": []})
    assert "api.anthropic.com" in p.static_hosts


def test_session_singletons():
    reset_session_store()
    s1 = session_store()
    s2 = session_store()
    assert s1 is s2
    set_session_profile(TargetProfile(name="t"))
    assert session_profile().name == "t"
