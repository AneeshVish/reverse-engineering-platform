"""Investigation manager.

Owns the investigation builder, validator, query engine, and serializers, and
participates in the substrate lifecycle via the ``Component`` shape. It organizes
existing inferences into cases; it performs no new reasoning.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .builders import InvestigationBuilder, InvestigationView
from .case import InvestigationCase
from .config import InvestigationConfig
from .query import InvestigationQuery, InvestigationQueryResult
from .serialization import InvestigationDeserializer, InvestigationSerializer
from .validation import validate_case

__all__ = ["InvestigationManager"]


class InvestigationManager:
    """Lifecycle-aware facade over investigation construction and access."""

    component_name = "investigation.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(self, config: InvestigationConfig | None = None) -> None:
        self._config = config or InvestigationConfig()
        self._builder = InvestigationBuilder()
        self._serializer = InvestigationSerializer()
        self._deserializer = InvestigationDeserializer()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Stateless; ready immediately."""

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- construction / query / validation / serialization -------------------

    def build(
        self,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> InvestigationCase:
        return self._builder.build(graph, evidence, reasoning)

    def build_view(
        self,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> InvestigationView:
        return self._builder.build_view(graph, evidence, reasoning)

    def query(
        self, case: InvestigationCase, query: InvestigationQuery
    ) -> InvestigationQueryResult:
        return query.run(case)

    def validate(
        self,
        case: InvestigationCase,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> None:
        validate_case(case, graph, evidence, reasoning)

    def serialize(self, case: InvestigationCase) -> str:
        return self._serializer.serialize(case)

    def deserialize(self, data: str) -> InvestigationCase:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail="investigation manager ready")

    def health_state(self) -> HealthState:
        return self.health().state
