"""Function-recovery framework.

Immutable records describing candidate functions and their boundaries. This is
framework structure only — no function-recovery algorithm is implemented in this
phase; analyzers that populate these remain placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["FunctionBoundary", "FunctionMetadata", "FunctionCandidate"]


@dataclass(frozen=True)
class FunctionBoundary:
    """The start (and optional end) address of a candidate function."""

    start: int
    end: int | None = None


@dataclass(frozen=True)
class FunctionMetadata:
    """Descriptive metadata for a candidate function (no analysis)."""

    name: str = ""
    calling_convention: str = "unknown"


@dataclass(frozen=True)
class FunctionCandidate:
    """A candidate function: a boundary plus descriptive metadata."""

    boundary: FunctionBoundary
    metadata: FunctionMetadata = FunctionMetadata()
