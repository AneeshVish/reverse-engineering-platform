"""Knowledge-graph tests: indexes and queries."""

from __future__ import annotations

from _graph_helpers import build_sample
from reveng_knowledge_graph import (
    EdgeIndex,
    EvidenceIndex,
    GraphNodeKind,
    GraphQuery,
    GraphQueryFilter,
    KindIndex,
    KnowledgeGraphBuilder,
    NodeIndex,
    RelationshipKind,
)


def _graph():
    ir, ev = build_sample()
    return KnowledgeGraphBuilder().build(ir, ev)


def test_node_index_membership() -> None:
    graph = _graph()
    idx = NodeIndex.build(graph)
    for n in graph.nodes:
        assert idx.contains(n.id)
    assert idx.ids() == tuple(sorted(idx.ids()))


def test_edge_index_membership() -> None:
    graph = _graph()
    idx = EdgeIndex.build(graph)
    for e in graph.edges:
        assert idx.contains(e.id)


def test_kind_index() -> None:
    graph = _graph()
    idx = KindIndex.build(graph)
    assert len(idx.lookup(GraphNodeKind.SYMBOL)) == 3
    assert len(idx.lookup(GraphNodeKind.MODULE)) == 1
    assert idx.lookup(GraphNodeKind.NAMESPACE) == ()


def test_evidence_index() -> None:
    graph = _graph()
    idx = EvidenceIndex.build(graph)
    assert len(idx.keys()) == 2  # two evidence records


def test_query_by_node_kind_returns_only_nodes() -> None:
    graph = _graph()
    result = GraphQuery((GraphQueryFilter(node_kind=GraphNodeKind.SYMBOL),)).run(graph)
    assert len(result.nodes) == 3
    assert result.edges == ()


def test_query_by_relationship_returns_only_edges() -> None:
    graph = _graph()
    result = GraphQuery((GraphQueryFilter(relationship=RelationshipKind.CONTAINS),)).run(graph)
    assert result.nodes == ()
    assert len(result.edges) == 4


def test_empty_query_returns_all() -> None:
    graph = _graph()
    result = GraphQuery(()).run(graph)
    assert len(result.nodes) == len(graph.nodes)
    assert len(result.edges) == len(graph.edges)


def test_query_result_deterministic() -> None:
    graph = _graph()
    q = GraphQuery((GraphQueryFilter(node_kind=GraphNodeKind.EVIDENCE),))
    assert q.run(graph).node_ids() == q.run(graph).node_ids()
