"""Invariant: the Phase 009 public API is frozen.

Everything exported from ``reveng_knowledge_graph.__init__`` is the public API
established by Engineering Phase 009. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_knowledge_graph as kg

PHASE_009_PUBLIC_API = frozenset(
    {
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
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_009_PUBLIC_API - set(kg.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(kg.__all__) - PHASE_009_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_009_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in kg.__all__:
        assert hasattr(kg, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(kg.__all__) == len(set(kg.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in kg.__all__ if inspect.ismodule(getattr(kg, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
