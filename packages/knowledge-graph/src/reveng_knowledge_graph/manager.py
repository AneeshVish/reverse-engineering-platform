"""Knowledge-graph manager.

Owns the graph builder, validator, query engine, and serializers, and participates
in the substrate lifecycle via the ``Component`` shape. Performs no reasoning; it
records facts by building deterministic graphs from IR and evidence.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState
from reveng_intermediate_representation import IRModule
from reveng_storage_evidence import Evidence

from .builders import KnowledgeGraphBuilder
from .config import KnowledgeGraphConfig
from .graph import KnowledgeGraph
from .query import GraphQuery, GraphQueryResult
from .serialization import GraphDeserializer, GraphSerializer
from .validation import validate_graph

__all__ = ["KnowledgeGraphManager"]


class KnowledgeGraphManager:
    """Lifecycle-aware facade over graph construction, query, and serialization."""

    component_name = "knowledge-graph.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(self, config: KnowledgeGraphConfig | None = None) -> None:
        self._config = config or KnowledgeGraphConfig()
        self._builder = KnowledgeGraphBuilder()
        self._serializer = GraphSerializer()
        self._deserializer = GraphDeserializer()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Stateless; ready immediately."""

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- construction / validation / query / serialization -------------------

    def build(self, ir_module: IRModule, evidence: tuple[Evidence, ...] = ()) -> KnowledgeGraph:
        return self._builder.build(ir_module, evidence)

    def validate(self, graph: KnowledgeGraph) -> None:
        validate_graph(graph)

    def query(self, graph: KnowledgeGraph, query: GraphQuery) -> GraphQueryResult:
        return query.run(graph)

    def serialize(self, graph: KnowledgeGraph) -> str:
        return self._serializer.serialize(graph)

    def deserialize(self, data: str) -> KnowledgeGraph:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail="knowledge graph manager ready")

    def health_state(self) -> HealthState:
        return self.health().state
