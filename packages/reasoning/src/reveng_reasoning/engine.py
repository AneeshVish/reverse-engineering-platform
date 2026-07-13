"""The reasoning engine.

Consumes a ``KnowledgeGraph`` and an ``EvidenceRepository``, runs the planned
rules through the executor, and aggregates the produced inferences into an
immutable, deterministic ``ReasoningResult``. It emits ``Inference`` objects only
and never mutates its inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reveng_knowledge_graph import KnowledgeGraph
from reveng_storage_evidence import EvidenceRepository

from .executor import RuleExecutor
from .inference import Inference
from .planner import ReasoningPlan, ReasoningPlanner
from .registry import RuleRegistry
from .rules import RuleContext

__all__ = ["ReasoningResult", "ReasoningEngine"]


@dataclass(frozen=True)
class ReasoningResult:
    """An immutable, id-ordered set of derived inferences."""

    inferences: tuple[Inference, ...] = field(default_factory=tuple)

    def by_rule(self, rule_id: str) -> tuple[Inference, ...]:
        return tuple(i for i in self.inferences if i.explanation.rule_id == rule_id)

    def facts(self) -> tuple[str, ...]:
        return tuple(i.fact for i in self.inferences)

    def __len__(self) -> int:
        return len(self.inferences)


class ReasoningEngine:
    """Plans and runs rules over a graph and evidence repository."""

    def __init__(
        self,
        planner: ReasoningPlanner | None = None,
        executor: RuleExecutor | None = None,
    ) -> None:
        self._planner = planner or ReasoningPlanner()
        self._executor = executor or RuleExecutor()

    def plan(self, registry: RuleRegistry, graph: KnowledgeGraph) -> ReasoningPlan:
        return self._planner.plan(registry, graph)

    def run(
        self,
        registry: RuleRegistry,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
    ) -> ReasoningResult:
        plan = self._planner.plan(registry, graph)
        context = RuleContext(graph=graph, evidence=evidence)

        collected: dict[str, Inference] = {}
        for rule_id in plan.ordered_ids:
            rule = registry.get(rule_id)
            result = self._executor.execute(rule, context)
            for inference in result.inferences:
                collected[inference.id.value] = inference

        ordered = tuple(sorted(collected.values(), key=lambda i: i.id.value))
        return ReasoningResult(inferences=ordered)
