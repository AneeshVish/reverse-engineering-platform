"""Architecture-neutral instruction abstraction.

The framework names the architectures it can carry but embeds no ISA assumptions
and contains no decoder. Concrete disassembly belongs to later phases; here an
``InstructionModel`` is a neutral wrapper that references a canonical IR
``Instruction`` without knowing how to produce one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from reveng_intermediate_representation import Instruction

__all__ = ["Architecture", "InstructionModel"]


class Architecture(str, Enum):
    """Architectures the framework can represent (no ISA logic implied)."""

    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    POWERPC = "powerpc"
    RISCV = "riscv"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstructionModel:
    """A neutral placeholder pairing an address with a canonical IR instruction.

    No decoder produces these in this phase; the type exists so later ISA-specific
    analyzers have a stable, architecture-neutral shape to emit.
    """

    architecture: Architecture
    address: int
    instruction: Instruction | None = None
