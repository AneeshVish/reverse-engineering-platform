"""Exact-match reasoning queries.

Selects inferences by exact-match criteria — rule id, inference kind, an evidence
id, or a graph node id present in the explanation. There is no traversal or graph
algorithm; results are returned in id order.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .engine import ReasoningResult
from .inference import Inference, InferenceKind

__all__ = ["ReasoningQueryFilter", "ReasoningQuery", "ReasoningQueryResult"]


@dataclass(frozen=True)
class ReasoningQueryFilter:
    """Exact-match criteria; unset fields do not constrain the result."""

    rule_id: str | None = None
    kind: InferenceKind | None = None
    evidence_id: str | None = None
    node_id: str | None = None

    def matches(self, inference: Inference) -> bool:
        if self.rule_id is not None and inference.explanation.rule_id != self.rule_id:
            return False
        if self.kind is not None and inference.kind is not self.kind:
            return False
        if self.evidence_id is not None and self.evidence_id not in inference.explanation.input_evidence:
            return False
        if self.node_id is not None and self.node_id not in inference.explanation.input_nodes:
            return False
        return True


@dataclass(frozen=True)
class ReasoningQueryResult:
    """A deterministically-ordered result set."""

    inferences: tuple[Inference, ...] = field(default_factory=tuple)

    def ids(self) -> tuple[str, ...]:
        return tuple(i.id.value for i in self.inferences)

    def __len__(self) -> int:
        return len(self.inferences)


@dataclass(frozen=True)
class ReasoningQuery:
    """A conjunction of exact-match filters."""

    filters: tuple[ReasoningQueryFilter, ...] = ()

    def run(self, result: ReasoningResult) -> ReasoningQueryResult:
        selected = tuple(
            i for i in result.inferences if all(f.matches(i) for f in self.filters)
        )
        return ReasoningQueryResult(selected)
