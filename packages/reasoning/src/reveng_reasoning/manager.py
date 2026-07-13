"""Reasoning manager.

Owns the rule registry, engine, validator, and serializers, and participates in
the substrate lifecycle via the ``Component`` shape. ``initialize`` registers the
built-in reference rules. Performs no reasoning of its own beyond orchestration.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState
from reveng_knowledge_graph import KnowledgeGraph
from reveng_storage_evidence import EvidenceRepository

from .config import ReasoningConfig
from .engine import ReasoningEngine, ReasoningResult
from .planner import ReasoningPlan
from .query import ReasoningQuery, ReasoningQueryResult
from .registry import RuleRegistry
from .rules import Rule
from .serialization import ReasoningDeserializer, ReasoningSerializer
from .validation import validate_result

__all__ = ["ReasoningManager"]


class ReasoningManager:
    """Lifecycle-aware facade over the reasoning engine."""

    component_name = "reasoning.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        engine: ReasoningEngine | None = None,
        config: ReasoningConfig | None = None,
        *,
        auto_register_builtins: bool = True,
    ) -> None:
        self._registry = registry or RuleRegistry()
        self._engine = engine or ReasoningEngine()
        self._config = config or ReasoningConfig()
        self._serializer = ReasoningSerializer()
        self._deserializer = ReasoningDeserializer()
        self._auto_register_builtins = auto_register_builtins

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Register the built-in reference rules unless preloaded."""

        if self._auto_register_builtins and len(self._registry) == 0:
            from .reference import register_builtin_rules

            register_builtin_rules(self._registry, self._config)

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- registration & execution -------------------------------------------

    @property
    def registry(self) -> RuleRegistry:
        return self._registry

    @property
    def config(self) -> ReasoningConfig:
        return self._config

    def register(self, rule: Rule) -> None:
        self._registry.register(rule)

    def plan(self, graph: KnowledgeGraph) -> ReasoningPlan:
        return self._engine.plan(self._registry, graph)

    def run(self, graph: KnowledgeGraph, evidence: EvidenceRepository) -> ReasoningResult:
        return self._engine.run(self._registry, graph, evidence)

    def query(self, result: ReasoningResult, query: ReasoningQuery) -> ReasoningQueryResult:
        return query.run(result)

    def validate(
        self, result: ReasoningResult, graph: KnowledgeGraph, evidence: EvidenceRepository
    ) -> None:
        validate_result(result, graph, evidence)

    def serialize(self, result: ReasoningResult) -> str:
        return self._serializer.serialize(result)

    def deserialize(self, data: str) -> ReasoningResult:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail=f"{len(self._registry)} rules")

    def health_state(self) -> HealthState:
        return self.health().state
