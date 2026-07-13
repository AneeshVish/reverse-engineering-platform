"""Canonical type model.

Immutable, representation-only type descriptions. No layout recovery, no size
inference, no analysis — these types simply describe what a producer or later
transform has already determined.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "IRType",
    "PrimitiveType",
    "PointerType",
    "ArrayType",
    "StructureType",
    "UnionType",
    "EnumType",
    "FunctionSignature",
]


@dataclass(frozen=True)
class IRType:
    """Base of the canonical type hierarchy."""

    name: str

    @property
    def type_kind(self) -> str:
        return type(self).__name__


@dataclass(frozen=True)
class PrimitiveType(IRType):
    """A primitive scalar type with an optional declared bit width."""

    bit_width: int = 0


@dataclass(frozen=True)
class PointerType(IRType):
    """A pointer to a pointee type."""

    pointee: IRType | None = None


@dataclass(frozen=True)
class ArrayType(IRType):
    """An array of a element type with an optional element count."""

    element: IRType | None = None
    count: int | None = None


@dataclass(frozen=True)
class StructureType(IRType):
    """A structure as an ordered sequence of named fields (no offsets)."""

    fields: tuple[tuple[str, IRType], ...] = ()


@dataclass(frozen=True)
class UnionType(IRType):
    """A union as a set of named variant types."""

    variants: tuple[tuple[str, IRType], ...] = ()


@dataclass(frozen=True)
class EnumType(IRType):
    """An enumeration as ordered (name, value) members."""

    members: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class FunctionSignature(IRType):
    """A function signature: return type, parameter types, variadic flag."""

    return_type: IRType | None = None
    parameters: tuple[IRType, ...] = field(default_factory=tuple)
    variadic: bool = False
