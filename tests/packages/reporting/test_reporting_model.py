"""Reporting tests: report/section model and immutability."""

from __future__ import annotations

import dataclasses

import pytest
from reveng_reporting import (
    Report,
    ReportID,
    ReportSection,
    ReportState,
    SectionKind,
)


def test_report_id_is_content_derived() -> None:
    a = ReportID.of("case1", "technical", 1)
    b = ReportID.of("case1", "technical", 1)
    assert a == b
    assert a.value != ReportID.of("case1", "technical", 2).value
    assert a.value != ReportID.of("case2", "technical", 1).value
    assert a.value != ReportID.of("case1", "evidence", 1).value


def test_report_id_is_sha256_hex() -> None:
    v = ReportID.of("c", "t", 1).value
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_section_is_immutable() -> None:
    s = ReportSection(SectionKind.SUMMARY, "Summary", "content")
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.title = "x"  # type: ignore[misc]


def test_report_is_immutable() -> None:
    report = Report(
        id=ReportID.of("c", "t", 1),
        case_id="c",
        template="t",
        title="title",
        summary="summary",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.title = "x"  # type: ignore[misc]


def test_report_states() -> None:
    assert {s.value for s in ReportState} == {"draft", "final", "archived"}


def test_section_kinds() -> None:
    assert {k.value for k in SectionKind} == {
        "summary",
        "findings",
        "inferences",
        "evidence",
        "graph",
        "appendix",
    }


def test_references_deduplicates_and_sorts() -> None:
    report = Report(
        id=ReportID.of("c", "t", 1),
        case_id="c",
        template="t",
        title="title",
        summary="summary",
        sections=(
            ReportSection(SectionKind.FINDINGS, "F", "c", ("b", "a")),
            ReportSection(SectionKind.EVIDENCE, "E", "c", ("a", "z")),
        ),
    )
    assert report.references() == ("a", "b", "z")
