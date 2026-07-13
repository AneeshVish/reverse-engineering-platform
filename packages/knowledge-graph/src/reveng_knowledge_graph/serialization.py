"""Canonical, deterministic graph serialization.

Serializes a ``KnowledgeGraph`` to canonical JSON: nodes sorted by id, edges
sorted by id, object keys sorted. The same graph always serializes to identical
bytes, and a round-trip reproduces an equal graph. No persistence backend.
"""

from __future__ import annotations

import json
from typing import Any

from .edges import GraphEdge, GraphEdgeID, RelationshipKind
from .errors import SerializationError
from .graph import KnowledgeGraph
from .nodes import GraphNode, GraphNodeID, GraphNodeKind
from .properties import PropertyBag

__all__ = ["GraphSerializer", "GraphDeserializer"]


def _enc_node(node: GraphNode) -> dict[str, Any]:
    return {
        "id": node.id.value,
        "kind": node.kind.value,
        "logical_key": node.logical_key,
        "name": node.name,
        "properties": {k: v for k, v in node.properties.items()},
    }


def _dec_node(raw: Any) -> GraphNode:
    return GraphNode(
        id=GraphNodeID(raw["id"]),
        kind=GraphNodeKind(raw["kind"]),
        logical_key=raw["logical_key"],
        name=raw.get("name", ""),
        properties=PropertyBag.of(dict(raw.get("properties", {}))),
    )


def _enc_edge(edge: GraphEdge) -> dict[str, Any]:
    return {
        "id": edge.id.value,
        "relationship": edge.relationship.value,
        "source": edge.source.value,
        "target": edge.target.value,
        "properties": {k: v for k, v in edge.properties.items()},
    }


def _dec_edge(raw: Any) -> GraphEdge:
    return GraphEdge(
        id=GraphEdgeID(raw["id"]),
        relationship=RelationshipKind(raw["relationship"]),
        source=GraphNodeID(raw["source"]),
        target=GraphNodeID(raw["target"]),
        properties=PropertyBag.of(dict(raw.get("properties", {}))),
    )


class GraphSerializer:
    """Serializes a ``KnowledgeGraph`` to canonical JSON text."""

    def serialize(self, graph: KnowledgeGraph) -> str:
        nodes = sorted((_enc_node(n) for n in graph.nodes), key=lambda d: d["id"])
        edges = sorted((_enc_edge(e) for e in graph.edges), key=lambda d: d["id"])
        payload = {"version": graph.version, "nodes": nodes, "edges": edges}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class GraphDeserializer:
    """Reconstructs a ``KnowledgeGraph`` from canonical JSON text."""

    def deserialize(self, data: str) -> KnowledgeGraph:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid graph document", detail=str(exc)) from exc
        nodes = tuple(_dec_node(n) for n in payload.get("nodes", []))
        edges = tuple(_dec_edge(e) for e in payload.get("edges", []))
        return KnowledgeGraph(nodes=nodes, edges=edges, version=payload.get("version", 1))
