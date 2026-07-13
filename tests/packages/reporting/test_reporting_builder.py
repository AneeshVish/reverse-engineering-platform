"""Reporting tests: report construction from an investigation case."""

from __future__ import annotations

from _reporting_helpers import build_pipeline, valid_ids
from reveng_reporting import (
    ExecutiveSummaryTemplate,
    ReportBuilder,
    ReportID,
    ReportState,
    TechnicalTemplate,
)


def _report(template=None):
    case, reasoning, repo, graph = build_pipeline()
    return ReportBuilder().build(case, reasoning, repo, graph, template)


def test_report_has_expected_metadata() -> None:
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    assert report.case_id == case.id.value
    assert report.template == "technical"
    assert report.state is ReportState.DRAFT
    assert report.version == 1


def test_report_id_derives_from_case_template_version() -> None:
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    assert report.id == ReportID.of(case.id.value, "technical", 1)


def test_default_template_is_executive_summary() -> None:
    report = _report()
    assert report.template == "executive_summary"


def test_technical_template_sections() -> None:
    report = _report(TechnicalTemplate())
    assert report.section_kinds() == ("summary", "findings", "inferences", "evidence", "graph")


def test_executive_summary_sections() -> None:
    report = _report(ExecutiveSummaryTemplate())
    assert report.section_kinds() == ("summary", "findings")


def test_all_references_resolve() -> None:
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    universe = valid_ids(case, reasoning, repo, graph)
    for ref in report.references():
        assert ref in universe


def test_deterministic_repeated_builds() -> None:
    case, reasoning, repo, graph = build_pipeline()
    a = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    b = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    assert a.id == b.id
    assert a.section_kinds() == b.section_kinds()


def test_different_template_different_id() -> None:
    case, reasoning, repo, graph = build_pipeline()
    a = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    b = ReportBuilder().build(case, reasoning, repo, graph, ExecutiveSummaryTemplate())
    assert a.id != b.id


def test_builder_does_not_mutate_inputs() -> None:
    case, reasoning, repo, graph = build_pipeline()
    before = (len(case.findings), len(reasoning), len(repo), len(graph.nodes))
    ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    after = (len(case.findings), len(reasoning), len(repo), len(graph.nodes))
    assert before == after


def test_severity_property_stamped() -> None:
    report = _report(TechnicalTemplate())
    assert report.properties.contains("severities")
    assert report.properties.get("finding_count") == 4
