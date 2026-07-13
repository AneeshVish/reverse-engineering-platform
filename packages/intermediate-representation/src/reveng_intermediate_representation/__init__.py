"""reveng-intermediate-representation — the canonical program representation.

Owner: Implementation Specification 004 (Canonical IR). This package is the
immutable language the rest of the platform speaks. It owns only the data model
and construction APIs: nodes, edges, instructions, types, symbols, metadata,
deterministic identities, builders, structural validation, and canonical
serialization.

It performs no analysis. It never parses binaries, disassembles, resolves
symbols, reasons, or stores anything. Every public object is immutable and is
constructed only through builders; transformations always return new IR.

Everything re-exported here constitutes the frozen Phase 006 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .builders import (
    FunctionBuilder,
    InstructionBuilder,
    IRBuilder,
    ModuleBuilder,
)
from .config import IR_DEFAULTS, IRConfig, load_ir_config
from .contracts import IRConsumer, IRProvider, IRTransform
from .edges import EdgeKind, IREdge
from .errors import (
    ConstructionError,
    IdentityError,
    RepresentationError,
    SerializationError,
    ValidationError,
    guard,
    make_error,
)
from .identity import IRIdentifier, IRNamespace, IRPath, derive_identifier
from .init import build_ir_manager
from .instructions import (
    ImmediateOperand,
    Instruction,
    MemoryOperand,
    Operand,
    OperandKind,
    RegisterOperand,
    UnknownOperand,
)
from .manager import IRManager
from .metadata import MetadataBag, MetadataKey, MetadataValue
from .nodes import (
    BasicBlockNode,
    ClassNode,
    DataNode,
    ExportNode,
    FunctionNode,
    ImportNode,
    InstructionNode,
    IRModule,
    IRNode,
    MethodNode,
    ModuleNode,
    NamespaceNode,
    NodeKind,
    SectionNode,
    SegmentNode,
    StringNode,
    SymbolNode,
    TypeNode,
)
from .serialization import IRDeserializer, IRSerializer
from .symbols import Binding, Symbol, SymbolKind, Visibility
from .types import (
    ArrayType,
    EnumType,
    FunctionSignature,
    IRType,
    PointerType,
    PrimitiveType,
    StructureType,
    UnionType,
)
from .validation import IRValidator, validate_module

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # identity
    "IRIdentifier",
    "IRPath",
    "IRNamespace",
    "derive_identifier",
    # metadata
    "MetadataKey",
    "MetadataValue",
    "MetadataBag",
    # types
    "IRType",
    "PrimitiveType",
    "PointerType",
    "ArrayType",
    "StructureType",
    "UnionType",
    "EnumType",
    "FunctionSignature",
    # symbols
    "Symbol",
    "SymbolKind",
    "Visibility",
    "Binding",
    # instructions
    "Instruction",
    "Operand",
    "OperandKind",
    "RegisterOperand",
    "ImmediateOperand",
    "MemoryOperand",
    "UnknownOperand",
    # nodes
    "NodeKind",
    "IRNode",
    "ModuleNode",
    "SectionNode",
    "SegmentNode",
    "NamespaceNode",
    "TypeNode",
    "ClassNode",
    "FunctionNode",
    "MethodNode",
    "BasicBlockNode",
    "InstructionNode",
    "DataNode",
    "StringNode",
    "SymbolNode",
    "ImportNode",
    "ExportNode",
    "IRModule",
    # edges
    "EdgeKind",
    "IREdge",
    # builders
    "IRBuilder",
    "ModuleBuilder",
    "FunctionBuilder",
    "InstructionBuilder",
    # validation
    "validate_module",
    "IRValidator",
    # serialization
    "IRSerializer",
    "IRDeserializer",
    # contracts
    "IRProvider",
    "IRConsumer",
    "IRTransform",
    # config
    "IRConfig",
    "load_ir_config",
    "IR_DEFAULTS",
    # manager
    "IRManager",
    "build_ir_manager",
    # errors
    "RepresentationError",
    "ValidationError",
    "ConstructionError",
    "IdentityError",
    "SerializationError",
    "make_error",
    "guard",
]
