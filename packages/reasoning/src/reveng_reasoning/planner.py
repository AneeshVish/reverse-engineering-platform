"""Deterministic rule planning.

Selects the rules applicable to a graph and returns an immutable, deterministic
``ReasoningPlan``. Ordering is by descending priority then registration order, so
identical inputs always yield an identical plan.
"""

from __future__ import annotations

from dataclasses import dataclass

from reveng_knowledge_graph import KnowledgeGraph

from .registry import RuleRegistry

__all__ = ["ReasoningPlan", "ReasoningPlanner"]


@dataclass(frozen=True)
class ReasoningPlan:
    """An immutable, deterministic ordering of rule identifiers to run."""

    ordered_ids: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.ordered_ids)


class ReasoningPlanner:
    """Deterministic rule selection over a registry."""

    def plan(self, registry: RuleRegistry, graph: KnowledgeGraph) -> ReasoningPlan:
        rules = registry.all()
        reg_index = {r.metadata.identifier: i for i, r in enumerate(rules)}
        applicable = [r for r in rules if r.applies_to(graph)]
        ordered = sorted(
            applicable,
            key=lambda r: (-r.metadata.priority, reg_index[r.metadata.identifier]),
        )
        return ReasoningPlan(tuple(r.metadata.identifier for r in ordered))
