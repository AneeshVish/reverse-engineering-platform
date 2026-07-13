"""Graph node model.

Immutable nodes with content-derived identity. A node's identity is
``SHA256(kind | logical_key)`` where the logical key comes from an existing
identity (an IR identifier, an evidence id, or an artifact content hash) — no new
identity scheme is introduced.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = ["GraphNodeKind", "GraphNodeID", "GraphNode"]

_SEP = "|"


class GraphNodeKind(str, Enum):
    MODULE = "module"
    FUNCTION = "function"
    SYMBOL = "symbol"
    SECTION = "section"
    STRING = "string"
    RESOURCE = "resource"
    ARTIFACT = "artifact"
    EVIDENCE = "evidence"
    NAMESPACE = "namespace"


@dataclass(frozen=True)
class GraphNodeID:
    """A content-derived node identity (hex SHA-256)."""

    value: str

    @classmethod
    def of(cls, kind: GraphNodeKind, logical_key: str) -> GraphNodeID:
        digest = hashlib.sha256(_SEP.join((kind.value, logical_key)).encode("utf-8"))
        return cls(digest.hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class GraphNode:
    """An immutable graph node."""

    id: GraphNodeID
    kind: GraphNodeKind
    logical_key: str
    name: str = ""
    properties: PropertyBag = EMPTY_PROPERTIES
