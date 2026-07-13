"""Graph validation.

Structural only: duplicate node ids, dangling edges (an endpoint that is not a
node), duplicate relationships (the same edge id twice), and invalid references.
No semantic validation.
"""

from __future__ import annotations

from .errors import ValidationError
from .graph import KnowledgeGraph

__all__ = ["validate_graph", "GraphValidator"]


def validate_graph(graph: KnowledgeGraph) -> None:
    """Validate ``graph`` structurally, raising ``ValidationError`` on failure."""

    node_ids: set[str] = set()
    for node in graph.nodes:
        if not node.id.value:
            raise ValidationError("node has empty id", logical_key=node.logical_key)
        if node.id.value in node_ids:
            raise ValidationError("duplicate node id", node=node.id.value)
        node_ids.add(node.id.value)

    edge_ids: set[str] = set()
    for edge in graph.edges:
        if edge.id.value in edge_ids:
            raise ValidationError("duplicate relationship", edge=edge.id.value)
        edge_ids.add(edge.id.value)
        if edge.source.value not in node_ids:
            raise ValidationError("dangling edge source", source=edge.source.value)
        if edge.target.value not in node_ids:
            raise ValidationError("dangling edge target", target=edge.target.value)


class GraphValidator:
    """Object wrapper around :func:`validate_graph`."""

    def validate(self, graph: KnowledgeGraph) -> None:
        validate_graph(graph)
