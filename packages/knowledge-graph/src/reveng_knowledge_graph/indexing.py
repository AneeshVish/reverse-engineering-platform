"""Deterministic graph indexes.

Dict-backed exact-lookup indexes with ``build`` classmethods and sorted,
deterministic results. No search or traversal algorithms.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .edges import GraphEdgeID
from .graph import KnowledgeGraph
from .nodes import GraphNodeID, GraphNodeKind

__all__ = ["NodeIndex", "EdgeIndex", "KindIndex", "EvidenceIndex"]


def _sorted_node_ids(ids: Iterable[GraphNodeID]) -> tuple[GraphNodeID, ...]:
    return tuple(sorted(set(ids), key=lambda i: i.value))


@dataclass(frozen=True)
class NodeIndex:
    """Membership/lookup of node ids."""

    _ids: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def build(cls, graph: KnowledgeGraph) -> NodeIndex:
        return cls(frozenset(n.id.value for n in graph.nodes))

    def contains(self, node_id: GraphNodeID) -> bool:
        return node_id.value in self._ids

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._ids))


@dataclass(frozen=True)
class EdgeIndex:
    """Membership/lookup of edge ids."""

    _ids: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def build(cls, graph: KnowledgeGraph) -> EdgeIndex:
        return cls(frozenset(e.id.value for e in graph.edges))

    def contains(self, edge_id: GraphEdgeID) -> bool:
        return edge_id.value in self._ids

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._ids))


@dataclass(frozen=True)
class KindIndex:
    """Maps a node kind to the node ids of that kind."""

    _by_kind: tuple[tuple[GraphNodeKind, tuple[GraphNodeID, ...]], ...] = ()

    @classmethod
    def build(cls, graph: KnowledgeGraph) -> KindIndex:
        buckets: dict[GraphNodeKind, list[GraphNodeID]] = {}
        for node in graph.nodes:
            buckets.setdefault(node.kind, []).append(node.id)
        rows = tuple(
            (k, _sorted_node_ids(v)) for k, v in sorted(buckets.items(), key=lambda kv: kv[0].value)
        )
        return cls(rows)

    def lookup(self, kind: GraphNodeKind) -> tuple[GraphNodeID, ...]:
        for k, ids in self._by_kind:
            if k is kind:
                return ids
        return ()


@dataclass(frozen=True)
class EvidenceIndex:
    """Maps an evidence logical key to the evidence node and its incident edges."""

    _nodes: tuple[tuple[str, GraphNodeID], ...] = ()

    @classmethod
    def build(cls, graph: KnowledgeGraph) -> EvidenceIndex:
        rows = tuple(
            sorted(
                (
                    (n.logical_key, n.id)
                    for n in graph.nodes
                    if n.kind is GraphNodeKind.EVIDENCE
                ),
                key=lambda kv: kv[0],
            )
        )
        return cls(rows)

    def lookup(self, evidence_key: str) -> GraphNodeID | None:
        for key, node_id in self._nodes:
            if key == evidence_key:
                return node_id
        return None

    def keys(self) -> tuple[str, ...]:
        return tuple(k for k, _ in self._nodes)
