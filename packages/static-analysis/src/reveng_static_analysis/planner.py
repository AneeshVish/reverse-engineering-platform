"""Analysis planning.

Selects the analyzers applicable to a request's artifact type and returns a
deterministic, immutable ``AnalysisPlan``. Ordering is by descending priority
then registration order, so identical inputs always yield an identical plan.
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import AnalysisRequest
from .registry import AnalyzerRegistry

__all__ = ["AnalysisPlan", "AnalysisPlanner"]


@dataclass(frozen=True)
class AnalysisPlan:
    """An immutable, deterministic ordering of analyzer identifiers to run."""

    ordered_ids: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.ordered_ids)


class AnalysisPlanner:
    """Deterministic analyzer selection over a registry."""

    def plan(self, registry: AnalyzerRegistry, request: AnalysisRequest) -> AnalysisPlan:
        analyzers = registry.all()
        reg_index = {a.metadata.identifier: i for i, a in enumerate(analyzers)}

        applicable = [a for a in analyzers if a.applies_to(request.artifact)]
        ordered = sorted(
            applicable,
            key=lambda a: (-a.metadata.priority, reg_index[a.metadata.identifier]),
        )
        return AnalysisPlan(tuple(a.metadata.identifier for a in ordered))
