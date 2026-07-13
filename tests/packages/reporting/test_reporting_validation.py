"""Reporting tests: report validation failures."""

from __future__ import annotations

import pytest
from _reporting_helpers import build_pipeline
from reveng_reporting import (
    Report,
    ReportBuilder,
    ReportID,
    ReportSection,
    SectionKind,
    TechnicalTemplate,
    ValidationError,
    validate_report,
)


def test_valid_report_passes() -> None:
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    validate_report(report, case, reasoning, repo, graph)  # no raise


def test_missing_reference_rejected() -> None:
    case, reasoning, repo, graph = build_pipeline()
    bad = Report(
        id=ReportID.of(case.id.value, "t", 1),
        case_id=case.id.value,
        template="t",
        title="title",
        summary="summary",
        sections=(ReportSection(SectionKind.FINDINGS, "F", "c", ("ghost-id",)),),
    )
    with pytest.raises(ValidationError):
        validate_report(bad, case, reasoning, repo, graph)


def test_duplicate_section_rejected() -> None:
    case, reasoning, repo, graph = build_pipeline()
    bad = Report(
        id=ReportID.of(case.id.value, "t", 1),
        case_id=case.id.value,
        template="t",
        title="title",
        summary="summary",
        sections=(
            ReportSection(SectionKind.SUMMARY, "S", "a"),
            ReportSection(SectionKind.SUMMARY, "S", "b"),
        ),
    )
    with pytest.raises(ValidationError):
        validate_report(bad, case, reasoning, repo, graph)


def test_empty_case_id_rejected() -> None:
    case, reasoning, repo, graph = build_pipeline()
    bad = Report(
        id=ReportID.of("x", "t", 1),
        case_id="",
        template="t",
        title="title",
        summary="summary",
    )
    with pytest.raises(ValidationError):
        validate_report(bad, case, reasoning, repo, graph)
