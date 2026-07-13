"""Architecture-neutral instruction abstraction.

An ``Instruction`` is a mnemonic plus operands. Raw architecture-specific detail
(encoding bytes, prefixes, precise addressing) lives in metadata, keeping the
canonical form architecture-neutral. No decoding or disassembly happens here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .metadata import EMPTY_METADATA, MetadataBag

__all__ = [
    "OperandKind",
    "Operand",
    "RegisterOperand",
    "ImmediateOperand",
    "MemoryOperand",
    "UnknownOperand",
    "Instruction",
]


class OperandKind(str, Enum):
    REGISTER = "register"
    IMMEDIATE = "immediate"
    MEMORY = "memory"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Operand:
    """Base operand. Subclasses specialize by kind."""

    kind: OperandKind = OperandKind.UNKNOWN
    metadata: MetadataBag = EMPTY_METADATA


@dataclass(frozen=True)
class RegisterOperand(Operand):
    register: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", OperandKind.REGISTER)


@dataclass(frozen=True)
class ImmediateOperand(Operand):
    value: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", OperandKind.IMMEDIATE)


@dataclass(frozen=True)
class MemoryOperand(Operand):
    expression: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", OperandKind.MEMORY)


@dataclass(frozen=True)
class UnknownOperand(Operand):
    raw: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", OperandKind.UNKNOWN)


@dataclass(frozen=True)
class Instruction:
    """An architecture-neutral instruction."""

    mnemonic: str
    operands: tuple[Operand, ...] = ()
    address: int | None = None
    metadata: MetadataBag = EMPTY_METADATA
