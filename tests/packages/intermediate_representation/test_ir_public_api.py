"""Invariant: the Phase 006 public API is frozen.

Everything exported from ``reveng_intermediate_representation.__init__`` is the
public API established by Engineering Phase 006. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_intermediate_representation as ir

PHASE_006_PUBLIC_API = frozenset(
    {
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
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_006_PUBLIC_API - set(ir.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(ir.__all__) - PHASE_006_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_006_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in ir.__all__:
        assert hasattr(ir, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(ir.__all__) == len(set(ir.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in ir.__all__ if inspect.ismodule(getattr(ir, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
