"""Base scaffolding and helpers for reference rules.

``ReferenceRule`` implements the ``Rule`` contract; concrete rules set a few class
attributes and override ``apply``. Small graph-lookup helpers keep the rules terse
and purely structural.
"""

from __future__ import annotations

from reveng_knowledge_graph import (
    GraphEdge,
    GraphNode,
    GraphNodeID,
    KnowledgeGraph,
    RelationshipKind,
)

from ..inference import InferenceKind
from ..rules import DEFAULT_PRIORITY, Rule, RuleMetadata, RuleRequirement

__all__ = ["ReferenceRule", "incoming", "outgoing", "node_name"]


class ReferenceRule(Rule):
    """Common, deterministic base for reference rules."""

    identifier_: str = ""
    version_: str = "1.0.0"
    inference_kind_: InferenceKind = InferenceKind.STRUCTURAL
    priority_: int = DEFAULT_PRIORITY
    description_: str = ""
    requirement_: RuleRequirement = RuleRequirement()

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            identifier=self.identifier_,
            version=self.version_,
            inference_kind=self.inference_kind_,
            priority=self.priority_,
            description=self.description_,
            requirement=self.requirement_,
        )


def incoming(
    graph: KnowledgeGraph, node_id: GraphNodeID, relationship: RelationshipKind
) -> tuple[GraphEdge, ...]:
    """Edges of a relationship pointing at ``node_id``."""

    return tuple(e for e in graph.edges_to(node_id) if e.relationship is relationship)


def outgoing(
    graph: KnowledgeGraph, node_id: GraphNodeID, relationship: RelationshipKind
) -> tuple[GraphEdge, ...]:
    """Edges of a relationship leaving ``node_id``."""

    return tuple(e for e in graph.edges_from(node_id) if e.relationship is relationship)


def node_name(node: GraphNode) -> str:
    return node.name or node.logical_key[:12]
