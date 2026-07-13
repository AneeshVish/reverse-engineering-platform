"""Canonical symbol model.

Immutable symbol descriptions. No resolution, binding computation, or address
assignment happens here — a ``Symbol`` records what has already been determined.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .metadata import EMPTY_METADATA, MetadataBag

__all__ = ["SymbolKind", "Visibility", "Binding", "Symbol"]


class SymbolKind(str, Enum):
    FUNCTION = "function"
    DATA = "data"
    SECTION = "section"
    IMPORT = "import"
    EXPORT = "export"
    LABEL = "label"
    UNKNOWN = "unknown"


class Visibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class Binding(str, Enum):
    LOCAL = "local"
    GLOBAL = "global"
    WEAK = "weak"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Symbol:
    """An immutable symbol description."""

    name: str
    kind: SymbolKind = SymbolKind.UNKNOWN
    visibility: Visibility = Visibility.UNKNOWN
    binding: Binding = Binding.UNKNOWN
    metadata: MetadataBag = EMPTY_METADATA
