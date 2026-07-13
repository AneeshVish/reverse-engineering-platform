"""Reporting tests: serialization, round-trip, indexing, and queries."""

from __future__ import annotations

from _reporting_helpers import build_pipeline
from reveng_reporting import (
    CaseIndex,
    ExecutiveSummaryTemplate,
    FindingIndex,
    Report,
    ReportBuilder,
    ReportDeserializer,
    ReportID,
    ReportIndex,
    ReportQuery,
    ReportQueryFilter,
    ReportSection,
    ReportSerializer,
    SectionKind,
    SeverityIndex,
    TechnicalTemplate,
)


def _report(template=None):
    case, reasoning, repo, graph = build_pipeline()
    return ReportBuilder().build(case, reasoning, repo, graph, template or TechnicalTemplate())


def test_serialization_is_deterministic() -> None:
    ser = ReportSerializer()
    assert ser.serialize(_report()) == ser.serialize(_report())


def test_round_trip_reproduces_equal_report() -> None:
    report = _report()
    data = ReportSerializer().serialize(report)
    restored = ReportDeserializer().deserialize(data)
    assert ReportSerializer().serialize(restored) == data


def test_round_trip_preserves_sections() -> None:
    report = _report()
    restored = ReportDeserializer().deserialize(ReportSerializer().serialize(report))
    assert restored.section_kinds() == report.section_kinds()
    assert restored.id == report.id


def _report_with_refs(references: tuple[str, ...]) -> Report:
    return Report(
        id=ReportID.of("c", "t", 1),
        case_id="c",
        template="t",
        title="title",
        summary="summary",
        sections=(ReportSection(SectionKind.FINDINGS, "F", "x", references),),
    )


def test_references_serialize_order_independent() -> None:
    # A section's references serialize sorted, so input order does not matter.
    a = _report_with_refs(("b", "a"))
    b = _report_with_refs(("a", "b"))
    assert ReportSerializer().serialize(a) == ReportSerializer().serialize(b)


def test_no_timestamp_in_output() -> None:
    data = ReportSerializer().serialize(_report())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data


def test_indexes() -> None:
    report = _report()
    reports = [report]
    assert ReportIndex.build(reports).contains(report.id.value)
    assert CaseIndex.build(reports).lookup(report.case_id) == (report.id.value,)
    fidx = FindingIndex.build(reports)
    for ref in report.references():
        assert report.id.value in fidx.lookup(ref)
    sev_idx = SeverityIndex.build(reports)
    assert report.id.value in sev_idx.lookup("high")


def test_query_by_template_and_case() -> None:
    case, reasoning, repo, graph = build_pipeline()
    tech = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    execu = ReportBuilder().build(case, reasoning, repo, graph, ExecutiveSummaryTemplate())
    reports = [tech, execu]

    by_template = ReportQuery((ReportQueryFilter(template="technical"),)).run(reports)
    assert by_template.ids() == (tech.id.value,)

    by_case = ReportQuery((ReportQueryFilter(case_id=case.id.value),)).run(reports)
    assert len(by_case) == 2


def test_query_by_severity() -> None:
    report = _report()
    out = ReportQuery((ReportQueryFilter(severity="high"),)).run([report])
    assert report.id.value in out.ids()


def test_query_deterministic() -> None:
    report = _report()
    q = ReportQuery(())
    assert q.run([report]).ids() == q.run([report]).ids()
