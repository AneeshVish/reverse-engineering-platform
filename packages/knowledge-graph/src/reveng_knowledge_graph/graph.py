"""The immutable knowledge graph.

A ``KnowledgeGraph`` is a frozen collection of nodes and edges with a version.
Nodes and edges are stored in deterministic (id-sorted) order. An update produces
a new versioned graph — the graph is never mutated in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .edges import GraphEdge, RelationshipKind
from .nodes import GraphNode, GraphNodeID, GraphNodeKind

__all__ = ["KnowledgeGraph"]


@dataclass(frozen=True)
class KnowledgeGraph:
    """An immutable graph of nodes and edges."""

    nodes: tuple[GraphNode, ...] = field(default_factory=tuple)
    edges: tuple[GraphEdge, ...] = field(default_factory=tuple)
    version: int = 1

    def node_by_id(self, node_id: GraphNodeID) -> GraphNode | None:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def node_ids(self) -> frozenset[GraphNodeID]:
        return frozenset(n.id for n in self.nodes)

    def nodes_of_kind(self, kind: GraphNodeKind) -> tuple[GraphNode, ...]:
        return tuple(n for n in self.nodes if n.kind is kind)

    def edges_of_kind(self, relationship: RelationshipKind) -> tuple[GraphEdge, ...]:
        return tuple(e for e in self.edges if e.relationship is relationship)

    def edges_from(self, node_id: GraphNodeID) -> tuple[GraphEdge, ...]:
        return tuple(e for e in self.edges if e.source == node_id)

    def edges_to(self, node_id: GraphNodeID) -> tuple[GraphEdge, ...]:
        return tuple(e for e in self.edges if e.target == node_id)

    def evolve(
        self, nodes: tuple[GraphNode, ...], edges: tuple[GraphEdge, ...]
    ) -> KnowledgeGraph:
        """Return a new graph version with the given nodes and edges."""

        return KnowledgeGraph(nodes=nodes, edges=edges, version=self.version + 1)

    def __len__(self) -> int:
        return len(self.nodes)
