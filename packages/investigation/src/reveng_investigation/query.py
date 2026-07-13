"""Exact-match investigation queries.

Selects findings from a case by exact-match criteria — finding kind, severity, an
evidence id, or an inference id present in the finding's explanation. There is no
graph traversal; results are returned in id order.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .case import InvestigationCase
from .finding import Finding, FindingKind, FindingSeverity

__all__ = ["InvestigationQueryFilter", "InvestigationQuery", "InvestigationQueryResult"]


@dataclass(frozen=True)
class InvestigationQueryFilter:
    """Exact-match criteria; unset fields do not constrain the result."""

    kind: FindingKind | None = None
    severity: FindingSeverity | None = None
    evidence_id: str | None = None
    inference_id: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.kind is not None and finding.kind is not self.kind:
            return False
        if self.severity is not None and finding.severity is not self.severity:
            return False
        if self.evidence_id is not None and self.evidence_id not in finding.explanation.evidence_ids:
            return False
        if self.inference_id is not None and self.inference_id not in finding.explanation.inference_ids:
            return False
        return True


@dataclass(frozen=True)
class InvestigationQueryResult:
    """A deterministically-ordered result set of findings."""

    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def ids(self) -> tuple[str, ...]:
        return tuple(f.id.value for f in self.findings)

    def __len__(self) -> int:
        return len(self.findings)


@dataclass(frozen=True)
class InvestigationQuery:
    """A conjunction of exact-match filters over a case's findings."""

    filters: tuple[InvestigationQueryFilter, ...] = ()

    def run(self, case: InvestigationCase) -> InvestigationQueryResult:
        selected = tuple(
            f for f in case.findings if all(flt.matches(f) for flt in self.filters)
        )
        return InvestigationQueryResult(selected)
