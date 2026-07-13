"""Exact-match report queries.

Selects reports from a collection by exact-match criteria — report id, case id,
template, a referenced finding id, or a severity label present in the report. No
search engine, no fuzzy matching; results are returned in report-id order.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .report import Report

__all__ = ["ReportQueryFilter", "ReportQuery", "ReportQueryResult"]


def _severities(report: Report) -> tuple[str, ...]:
    raw = report.properties.get("severities", "")
    if isinstance(raw, str) and raw:
        return tuple(raw.split(","))
    return ()


@dataclass(frozen=True)
class ReportQueryFilter:
    """Exact-match criteria; unset fields do not constrain the result."""

    report_id: str | None = None
    case_id: str | None = None
    template: str | None = None
    finding_id: str | None = None
    severity: str | None = None

    def matches(self, report: Report) -> bool:
        if self.report_id is not None and report.id.value != self.report_id:
            return False
        if self.case_id is not None and report.case_id != self.case_id:
            return False
        if self.template is not None and report.template != self.template:
            return False
        if self.finding_id is not None and self.finding_id not in report.references():
            return False
        if self.severity is not None and self.severity not in _severities(report):
            return False
        return True


@dataclass(frozen=True)
class ReportQueryResult:
    """A deterministically-ordered result set of reports."""

    reports: tuple[Report, ...] = field(default_factory=tuple)

    def ids(self) -> tuple[str, ...]:
        return tuple(r.id.value for r in self.reports)

    def __len__(self) -> int:
        return len(self.reports)


@dataclass(frozen=True)
class ReportQuery:
    """A conjunction of exact-match filters over a collection of reports."""

    filters: tuple[ReportQueryFilter, ...] = ()

    def run(self, reports: Iterable[Report]) -> ReportQueryResult:
        selected = tuple(
            r for r in reports if all(f.matches(r) for f in self.filters)
        )
        ordered = tuple(sorted(selected, key=lambda r: r.id.value))
        return ReportQueryResult(ordered)
