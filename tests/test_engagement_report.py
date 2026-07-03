"""Tests for engagement report and blue team output."""

from src.core.evidence_store import reset_session_store, session_store, EvidenceItem, L1
from src.core import engagement_report, blue_team


def test_html_report_contains_sections():
    html = engagement_report.generate_html(flows=[], behavior_infer_text="test infer")
    assert "RED TEAM Engagement Report" in html
    assert "Cannot Be Determined" in html


def test_blue_team_recommendations():
    reset_session_store()
    session_store().add(EvidenceItem(
        claim="Admin path exposed", level=L1, category="access_path", confidence="STRONG"))
    recs = blue_team.recommendations_from_evidence()
    assert recs
    text = blue_team.format_report(recs)
    assert "HARDENING" in text
