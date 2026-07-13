"""Relationship model.

An ``IREdge`` records a typed relationship between two nodes by identifier. Edges
carry only metadata; there is no traversal, query, or graph-algorithm behavior
here — that belongs to later analysis packages.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .identity import IRIdentifier
from .metadata import EMPTY_METADATA, MetadataBag

__all__ = ["EdgeKind", "IREdge"]


class EdgeKind(str, Enum):
    CONTAINS = "contains"
    REFERENCES = "references"
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    IMPORTS = "imports"
    EXPORTS = "exports"
    INHERITS = "inherits"
    IMPLEMENTS = "implements"
    USES = "uses"


@dataclass(frozen=True)
class IREdge:
    """A typed relationship from ``source`` to ``target`` (by identifier)."""

    kind: EdgeKind
    source: IRIdentifier
    target: IRIdentifier
    metadata: MetadataBag = EMPTY_METADATA
