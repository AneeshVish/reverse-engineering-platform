"""Graph edge model.

Immutable typed relationships between nodes with content-derived identity:
``SHA256(source | relationship | target)``. Relationships are factual only — there
are no inference relationships.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from .nodes import GraphNodeID
from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = ["RelationshipKind", "GraphEdgeID", "GraphEdge"]

_SEP = "|"


class RelationshipKind(str, Enum):
    CONTAINS = "contains"
    REFERENCES = "references"
    IMPLEMENTS = "implements"
    IMPORTS = "imports"
    EXPORTS = "exports"
    DERIVED_FROM = "derived_from"
    GENERATED_BY = "generated_by"
    OBSERVED_IN = "observed_in"


@dataclass(frozen=True)
class GraphEdgeID:
    """A content-derived edge identity (hex SHA-256)."""

    value: str

    @classmethod
    def of(
        cls, source: GraphNodeID, relationship: RelationshipKind, target: GraphNodeID
    ) -> GraphEdgeID:
        digest = hashlib.sha256(
            _SEP.join((source.value, relationship.value, target.value)).encode("utf-8")
        )
        return cls(digest.hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class GraphEdge:
    """An immutable typed relationship from ``source`` to ``target``."""

    id: GraphEdgeID
    relationship: RelationshipKind
    source: GraphNodeID
    target: GraphNodeID
    properties: PropertyBag = EMPTY_PROPERTIES
