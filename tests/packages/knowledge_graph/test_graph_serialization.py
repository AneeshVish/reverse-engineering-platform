"""Knowledge-graph tests: deterministic serialization and round-trip."""

from __future__ import annotations

import dataclasses

import pytest
from _graph_helpers import build_sample
from reveng_knowledge_graph import (
    GraphDeserializer,
    GraphSerializer,
    KnowledgeGraphBuilder,
    SerializationError,
)


def _graph():
    ir, ev = build_sample()
    return KnowledgeGraphBuilder().build(ir, ev)


def test_serialization_is_deterministic() -> None:
    a = _graph()
    b = _graph()
    assert GraphSerializer().serialize(a) == GraphSerializer().serialize(b)


def test_serialization_order_independent() -> None:
    graph = _graph()
    reversed_graph = dataclasses.replace(
        graph, nodes=tuple(reversed(graph.nodes)), edges=tuple(reversed(graph.edges))
    )
    assert GraphSerializer().serialize(graph) == GraphSerializer().serialize(reversed_graph)


def test_round_trip_reproduces_equal_graph() -> None:
    graph = _graph()
    data = GraphSerializer().serialize(graph)
    restored = GraphDeserializer().deserialize(data)
    assert GraphSerializer().serialize(restored) == data


def test_round_trip_preserves_structure() -> None:
    graph = _graph()
    restored = GraphDeserializer().deserialize(GraphSerializer().serialize(graph))
    assert len(restored.nodes) == len(graph.nodes)
    assert len(restored.edges) == len(graph.edges)
    assert restored.node_ids() == graph.node_ids()


def test_invalid_document_raises() -> None:
    with pytest.raises(SerializationError):
        GraphDeserializer().deserialize("{not json")


def test_no_timestamp_in_output() -> None:
    data = GraphSerializer().serialize(_graph())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data
