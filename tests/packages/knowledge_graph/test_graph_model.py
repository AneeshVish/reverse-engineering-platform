"""Knowledge-graph tests: node/edge model and content-derived identity."""

from __future__ import annotations

import dataclasses

import pytest
from reveng_knowledge_graph import (
    GraphEdge,
    GraphEdgeID,
    GraphNode,
    GraphNodeID,
    GraphNodeKind,
    PropertyBag,
    RelationshipKind,
)


def test_node_id_is_content_derived() -> None:
    a = GraphNodeID.of(GraphNodeKind.MODULE, "key1")
    b = GraphNodeID.of(GraphNodeKind.MODULE, "key1")
    assert a == b
    assert a.value != GraphNodeID.of(GraphNodeKind.MODULE, "key2").value
    assert a.value != GraphNodeID.of(GraphNodeKind.FUNCTION, "key1").value


def test_node_id_is_sha256_hex() -> None:
    v = GraphNodeID.of(GraphNodeKind.SYMBOL, "k").value
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_edge_id_is_content_derived() -> None:
    s = GraphNodeID.of(GraphNodeKind.MODULE, "s")
    t = GraphNodeID.of(GraphNodeKind.SYMBOL, "t")
    a = GraphEdgeID.of(s, RelationshipKind.CONTAINS, t)
    b = GraphEdgeID.of(s, RelationshipKind.CONTAINS, t)
    assert a == b
    assert a.value != GraphEdgeID.of(s, RelationshipKind.REFERENCES, t).value
    assert a.value != GraphEdgeID.of(t, RelationshipKind.CONTAINS, s).value  # direction matters


def test_node_is_immutable() -> None:
    node = GraphNode(
        id=GraphNodeID.of(GraphNodeKind.MODULE, "k"),
        kind=GraphNodeKind.MODULE,
        logical_key="k",
        name="m",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        node.name = "x"  # type: ignore[misc]


def test_edge_is_immutable() -> None:
    s = GraphNodeID.of(GraphNodeKind.MODULE, "s")
    t = GraphNodeID.of(GraphNodeKind.SYMBOL, "t")
    edge = GraphEdge(
        id=GraphEdgeID.of(s, RelationshipKind.CONTAINS, t),
        relationship=RelationshipKind.CONTAINS,
        source=s,
        target=t,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        edge.source = t  # type: ignore[misc]


def test_property_bag_key_sorted() -> None:
    bag = PropertyBag.of({"z": 1, "a": 2})
    assert bag.keys() == ("a", "z")


def test_no_inference_relationships() -> None:
    # The relationship vocabulary is factual only.
    values = {r.value for r in RelationshipKind}
    assert values == {
        "contains",
        "references",
        "implements",
        "imports",
        "exports",
        "derived_from",
        "generated_by",
        "observed_in",
    }
