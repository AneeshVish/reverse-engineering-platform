"""Exact-match graph queries.

A ``GraphQuery`` selects nodes or edges by exact-match criteria. There is no
traversal engine, shortest-path, or graph algorithm — only deterministic exact
selection returned in id order.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .edges import GraphEdge, RelationshipKind
from .graph import KnowledgeGraph
from .nodes import GraphNode, GraphNodeID, GraphNodeKind

__all__ = ["GraphQueryFilter", "GraphQuery", "GraphQueryResult"]


@dataclass(frozen=True)
class GraphQueryFilter:
    """Exact-match criteria; unset fields do not constrain the result."""

    node_kind: GraphNodeKind | None = None
    relationship: RelationshipKind | None = None
    source: GraphNodeID | None = None
    target: GraphNodeID | None = None

    def matches_node(self, node: GraphNode) -> bool:
        if self.node_kind is not None and node.kind is not self.node_kind:
            return False
        return True

    def matches_edge(self, edge: GraphEdge) -> bool:
        if self.relationship is not None and edge.relationship is not self.relationship:
            return False
        if self.source is not None and edge.source != self.source:
            return False
        if self.target is not None and edge.target != self.target:
            return False
        return True


@dataclass(frozen=True)
class GraphQueryResult:
    """A deterministically-ordered result of matched nodes and edges."""

    nodes: tuple[GraphNode, ...] = field(default_factory=tuple)
    edges: tuple[GraphEdge, ...] = field(default_factory=tuple)

    def node_ids(self) -> tuple[str, ...]:
        return tuple(n.id.value for n in self.nodes)

    def edge_ids(self) -> tuple[str, ...]:
        return tuple(e.id.value for e in self.edges)


@dataclass(frozen=True)
class GraphQuery:
    """A conjunction of exact-match filters over nodes and edges."""

    filters: tuple[GraphQueryFilter, ...] = ()

    def run(self, graph: KnowledgeGraph) -> GraphQueryResult:
        has_node_criteria = any(f.node_kind is not None for f in self.filters)
        has_edge_criteria = any(
            f.relationship is not None or f.source is not None or f.target is not None
            for f in self.filters
        )

        want_nodes = has_node_criteria or not has_edge_criteria
        want_edges = has_edge_criteria or not has_node_criteria

        nodes = (
            tuple(n for n in graph.nodes if all(f.matches_node(n) for f in self.filters))
            if want_nodes
            else ()
        )
        edges = (
            tuple(e for e in graph.edges if all(f.matches_edge(e) for f in self.filters))
            if want_edges
            else ()
        )
        return GraphQueryResult(nodes=nodes, edges=edges)
