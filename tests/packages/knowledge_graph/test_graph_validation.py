"""Knowledge-graph tests: structural validation failures."""

from __future__ import annotations

import pytest
from _graph_helpers import build_sample
from reveng_knowledge_graph import (
    GraphEdge,
    GraphEdgeID,
    GraphNode,
    GraphNodeID,
    GraphNodeKind,
    KnowledgeGraph,
    KnowledgeGraphBuilder,
    RelationshipKind,
    ValidationError,
    validate_graph,
)


def _node(key: str) -> GraphNode:
    nid = GraphNodeID.of(GraphNodeKind.MODULE, key)
    return GraphNode(id=nid, kind=GraphNodeKind.MODULE, logical_key=key, name=key)


def test_valid_graph_passes() -> None:
    ir, ev = build_sample()
    validate_graph(KnowledgeGraphBuilder().build(ir, ev))  # no raise


def test_duplicate_node_id_rejected() -> None:
    n = _node("a")
    graph = KnowledgeGraph(nodes=(n, n))
    with pytest.raises(ValidationError):
        validate_graph(graph)


def test_dangling_edge_rejected() -> None:
    n = _node("a")
    ghost = GraphNodeID.of(GraphNodeKind.SYMBOL, "ghost")
    edge = GraphEdge(
        id=GraphEdgeID.of(n.id, RelationshipKind.CONTAINS, ghost),
        relationship=RelationshipKind.CONTAINS,
        source=n.id,
        target=ghost,
    )
    graph = KnowledgeGraph(nodes=(n,), edges=(edge,))
    with pytest.raises(ValidationError):
        validate_graph(graph)


def test_duplicate_relationship_rejected() -> None:
    a, b = _node("a"), _node("b")
    edge = GraphEdge(
        id=GraphEdgeID.of(a.id, RelationshipKind.CONTAINS, b.id),
        relationship=RelationshipKind.CONTAINS,
        source=a.id,
        target=b.id,
    )
    graph = KnowledgeGraph(nodes=(a, b), edges=(edge, edge))
    with pytest.raises(ValidationError):
        validate_graph(graph)
