"""Exact-match evidence query.

A ``Query`` is a conjunction of exact-match ``QueryFilter`` predicates. There is
no regex, fuzzy matching, ranking, or search algorithm — only deterministic
exact selection over a repository's current evidence, returned in id order.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reveng_intermediate_representation import IRIdentifier

from .evidence import Evidence, EvidenceConfidence, EvidenceKind, EvidenceState
from .repository import EvidenceRepository

__all__ = ["QueryFilter", "Query", "QueryResult"]


@dataclass(frozen=True)
class QueryFilter:
    """Exact-match criteria; unset fields do not constrain the result."""

    kind: EvidenceKind | None = None
    state: EvidenceState | None = None
    confidence: EvidenceConfidence | None = None
    artifact_ref: str | None = None
    ir_ref: IRIdentifier | None = None

    def matches(self, evidence: Evidence) -> bool:
        if self.kind is not None and evidence.kind is not self.kind:
            return False
        if self.state is not None and evidence.state is not self.state:
            return False
        if self.confidence is not None and evidence.confidence is not self.confidence:
            return False
        if self.artifact_ref is not None and evidence.artifact_ref != self.artifact_ref:
            return False
        if self.ir_ref is not None and self.ir_ref not in evidence.ir_refs:
            return False
        return True


@dataclass(frozen=True)
class QueryResult:
    """A deterministically-ordered result set."""

    evidence: tuple[Evidence, ...] = field(default_factory=tuple)

    def ids(self) -> tuple[str, ...]:
        return tuple(e.id.value for e in self.evidence)

    def __len__(self) -> int:
        return len(self.evidence)


@dataclass(frozen=True)
class Query:
    """A conjunction of exact-match filters."""

    filters: tuple[QueryFilter, ...] = ()

    def run(self, repository: EvidenceRepository) -> QueryResult:
        selected = [
            e for e in repository.enumerate() if all(f.matches(e) for f in self.filters)
        ]
        return QueryResult(tuple(selected))
