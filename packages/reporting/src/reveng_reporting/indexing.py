"""Deterministic report indexes.

Dict-backed exact-lookup indexes over a collection of reports, with ``build``
classmethods and sorted, deterministic results. No search engine.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .report import Report

__all__ = ["ReportIndex", "CaseIndex", "FindingIndex", "SeverityIndex"]


def _report_severities(report: Report) -> tuple[str, ...]:
    raw = report.properties.get("severities", "")
    if isinstance(raw, str) and raw:
        return tuple(raw.split(","))
    return ()


@dataclass(frozen=True)
class ReportIndex:
    """Membership/lookup of report ids."""

    _ids: frozenset[str] = frozenset()

    @classmethod
    def build(cls, reports: Iterable[Report]) -> ReportIndex:
        return cls(frozenset(r.id.value for r in reports))

    def contains(self, report_id: str) -> bool:
        return report_id in self._ids

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._ids))


@dataclass(frozen=True)
class CaseIndex:
    """Maps a case id to the report ids built from it."""

    _by_case: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def build(cls, reports: Iterable[Report]) -> CaseIndex:
        buckets: dict[str, list[str]] = {}
        for report in reports:
            buckets.setdefault(report.case_id, []).append(report.id.value)
        rows = tuple((c, tuple(sorted(set(ids)))) for c, ids in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, case_id: str) -> tuple[str, ...]:
        for cid, ids in self._by_case:
            if cid == case_id:
                return ids
        return ()


@dataclass(frozen=True)
class FindingIndex:
    """Maps a referenced finding id to the report ids that cite it."""

    _by_finding: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def build(cls, reports: Iterable[Report]) -> FindingIndex:
        buckets: dict[str, list[str]] = {}
        for report in reports:
            for ref in report.references():
                buckets.setdefault(ref, []).append(report.id.value)
        rows = tuple((f, tuple(sorted(set(ids)))) for f, ids in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, finding_id: str) -> tuple[str, ...]:
        for fid, ids in self._by_finding:
            if fid == finding_id:
                return ids
        return ()


@dataclass(frozen=True)
class SeverityIndex:
    """Maps a severity label to the report ids that contain it."""

    _by_severity: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def build(cls, reports: Iterable[Report]) -> SeverityIndex:
        buckets: dict[str, list[str]] = {}
        for report in reports:
            for sev in _report_severities(report):
                buckets.setdefault(sev, []).append(report.id.value)
        rows = tuple((s, tuple(sorted(set(ids)))) for s, ids in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, severity: str) -> tuple[str, ...]:
        for sev, ids in self._by_severity:
            if sev == severity:
                return ids
        return ()
