"""reveng-knowledge-graph — the canonical semantic graph.

Owner: Implementation Specification 007 (Knowledge Graph). This package consumes
canonical IR and Evidence and constructs a deterministic, immutable graph of
nodes, edges, and properties. It records facts and relationships only — it
performs no reasoning, inference, scoring, ranking, graph algorithms, malware
detection, persistence, or AI.

Everything re-exported here constitutes the frozen Phase 009 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .builders import KnowledgeGraphBuilder
from .config import GRAPH_DEFAULTS, KnowledgeGraphConfig, load_graph_config
from .contracts import GraphBuilder, GraphConsumer, GraphProvider
from .edges import GraphEdge, GraphEdgeID, RelationshipKind
from .errors import (
    ConstructionError,
    GraphError,
    IdentityError,
    SerializationError,
    ValidationError,
    guard,
    make_error,
)
from .graph import KnowledgeGraph
from .indexing import EdgeIndex, EvidenceIndex, KindIndex, NodeIndex
from .init import build_knowledge_graph
from .manager import KnowledgeGraphManager
from .nodes import GraphNode, GraphNodeID, GraphNodeKind
from .properties import PropertyBag, PropertyKey, PropertyValue
from .query import GraphQuery, GraphQueryFilter, GraphQueryResult
from .serialization import GraphDeserializer, GraphSerializer
from .validation import GraphValidator, validate_graph

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # nodes
    "GraphNodeKind",
    "GraphNodeID",
    "GraphNode",
    # edges
    "RelationshipKind",
    "GraphEdgeID",
    "GraphEdge",
    # properties
    "PropertyKey",
    "PropertyValue",
    "PropertyBag",
    # graph
    "KnowledgeGraph",
    # builder
    "KnowledgeGraphBuilder",
    # validation
    "validate_graph",
    "GraphValidator",
    # indexing
    "NodeIndex",
    "EdgeIndex",
    "KindIndex",
    "EvidenceIndex",
    # query
    "GraphQuery",
    "GraphQueryFilter",
    "GraphQueryResult",
    # serialization
    "GraphSerializer",
    "GraphDeserializer",
    # contracts
    "GraphProvider",
    "GraphConsumer",
    "GraphBuilder",
    # config
    "KnowledgeGraphConfig",
    "load_graph_config",
    "GRAPH_DEFAULTS",
    # manager
    "KnowledgeGraphManager",
    "build_knowledge_graph",
    # errors
    "GraphError",
    "ConstructionError",
    "ValidationError",
    "SerializationError",
    "IdentityError",
    "make_error",
    "guard",
]
