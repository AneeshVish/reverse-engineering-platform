"""Tests for access path and controlled probes."""

from src.core import access_path_engine as ap
from src.core import access_validator
from src.core.engagement_scope import engagement_manager, EngagementScope


def test_discover_admin_endpoint():
    intel = {"endpoints": ["/api/admin/debug"], "hosts": ["staging.api.example.com"],
             "feature_flags": [{"name": "DEBUG_API", "file": "x.js"}], "hits": []}
    cands = ap.discover(architecture_intel=intel)
    types = {c.path_type for c in cands}
    assert "admin_endpoint" in types
    assert "staging_host" in types
    assert "debug_flag" in types


def test_probe_blocked_without_scope(monkeypatch):
    import src.core.engagement_scope as es
    from src.core import controlled_probe as cp
    monkeypatch.setattr(es, "SCOPE_GATE_ENABLED", True)
    mgr = engagement_manager()
    mgr.scope = EngagementScope()  # reset — no client/hosts
    cp._probe_count = 0
    r = cp.run_probe("invalid_json", "https://api.example.com/v1/test")
    assert r.get("skipped")


def test_probe_allowed_with_scope():
    from src.core import controlled_probe as cp
    mgr = engagement_manager()
    mgr.scope = EngagementScope(
        client="Test", scope_hosts=["api.example.com"], roe_acknowledged=True,
        allowed_actions=["passive_capture", "controlled_probe"],
    )
    cp._probe_count = 0
    # Will attempt HTTP — may fail network but should not skip for scope
    r = cp.run_probe("missing_auth", "https://api.example.com/v1/test")
    assert not r.get("skipped", True) or r.get("response") is not None
