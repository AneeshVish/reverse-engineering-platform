"""Cross-reference framework.

Immutable records describing a reference from one location to a target. This is
framework structure only — no reference-recovery algorithm is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["ReferenceKind", "ReferenceTarget", "CrossReference"]


class ReferenceKind(str, Enum):
    CALL = "call"
    JUMP = "jump"
    DATA = "data"
    STRING = "string"
    IMPORT = "import"
    EXPORT = "export"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReferenceTarget:
    """Where a reference points — a symbolic name and/or an address."""

    name: str = ""
    address: int | None = None


@dataclass(frozen=True)
class CrossReference:
    """A reference from ``source_address`` to ``target`` of a given kind."""

    kind: ReferenceKind
    source_address: int
    target: ReferenceTarget
