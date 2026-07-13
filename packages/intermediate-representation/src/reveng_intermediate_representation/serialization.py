"""Canonical, deterministic IR serialization.

Serializes an ``IRModule`` to canonical JSON: nodes sorted by identifier, edges
sorted by (kind, source, target), and object keys sorted. The same module always
serializes to identical bytes, and a round-trip reproduces an equal module. No
persistence backend and no timestamps are involved.
"""

from __future__ import annotations

import json
from typing import Any

from .edges import EdgeKind, IREdge
from .errors import SerializationError
from .identity import IRIdentifier, IRPath
from .instructions import (
    ImmediateOperand,
    Instruction,
    MemoryOperand,
    Operand,
    RegisterOperand,
    UnknownOperand,
)
from .metadata import EMPTY_METADATA, MetadataBag, MetadataValue
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

__all__ = ["IRSerializer", "IRDeserializer"]


# --- metadata ---------------------------------------------------------------


def _enc_metadata(bag: MetadataBag) -> dict[str, MetadataValue]:
    return {k: v for k, v in bag.items()}


def _dec_metadata(raw: Any) -> MetadataBag:
    if not raw:
        return EMPTY_METADATA
    return MetadataBag.of(dict(raw))


# --- types ------------------------------------------------------------------


def _enc_type(t: IRType | None) -> Any:
    if t is None:
        return None
    tk = t.type_kind
    base: dict[str, Any] = {"tk": tk, "name": t.name}
    if isinstance(t, PrimitiveType):
        base["bit_width"] = t.bit_width
    elif isinstance(t, PointerType):
        base["pointee"] = _enc_type(t.pointee)
    elif isinstance(t, ArrayType):
        base["element"] = _enc_type(t.element)
        base["count"] = t.count
    elif isinstance(t, StructureType):
        base["fields"] = [[n, _enc_type(ft)] for n, ft in t.fields]
    elif isinstance(t, UnionType):
        base["variants"] = [[n, ft and _enc_type(ft)] for n, ft in t.variants]
    elif isinstance(t, EnumType):
        base["members"] = [[n, v] for n, v in t.members]
    elif isinstance(t, FunctionSignature):
        base["return_type"] = _enc_type(t.return_type)
        base["parameters"] = [_enc_type(p) for p in t.parameters]
        base["variadic"] = t.variadic
    return base


def _dec_type(raw: Any) -> IRType | None:
    if raw is None:
        return None
    tk = raw["tk"]
    name = raw["name"]
    if tk == "PrimitiveType":
        return PrimitiveType(name=name, bit_width=raw.get("bit_width", 0))
    if tk == "PointerType":
        return PointerType(name=name, pointee=_dec_type(raw.get("pointee")))
    if tk == "ArrayType":
        return ArrayType(name=name, element=_dec_type(raw.get("element")), count=raw.get("count"))
    if tk == "StructureType":
        fields = tuple((n, _dec_type(ft)) for n, ft in raw.get("fields", []))
        return StructureType(name=name, fields=tuple((n, ft) for n, ft in fields if ft is not None))
    if tk == "UnionType":
        variants = tuple((n, _dec_type(ft)) for n, ft in raw.get("variants", []))
        return UnionType(name=name, variants=tuple((n, ft) for n, ft in variants if ft is not None))
    if tk == "EnumType":
        return EnumType(name=name, members=tuple((n, v) for n, v in raw.get("members", [])))
    if tk == "FunctionSignature":
        return FunctionSignature(
            name=name,
            return_type=_dec_type(raw.get("return_type")),
            parameters=tuple(p for p in (_dec_type(x) for x in raw.get("parameters", [])) if p),
            variadic=raw.get("variadic", False),
        )
    if tk == "IRType":
        return IRType(name=name)
    raise SerializationError("unknown type kind", tk=tk)


# --- operands / instructions ------------------------------------------------


def _enc_operand(op: Operand) -> dict[str, Any]:
    base: dict[str, Any] = {"ok": op.kind.value, "metadata": _enc_metadata(op.metadata)}
    if isinstance(op, RegisterOperand):
        base["register"] = op.register
    elif isinstance(op, ImmediateOperand):
        base["value"] = op.value
    elif isinstance(op, MemoryOperand):
        base["expression"] = op.expression
    elif isinstance(op, UnknownOperand):
        base["raw"] = op.raw
    return base


def _dec_operand(raw: Any) -> Operand:
    ok = raw["ok"]
    md = _dec_metadata(raw.get("metadata"))
    if ok == "register":
        return RegisterOperand(register=raw.get("register", ""), metadata=md)
    if ok == "immediate":
        return ImmediateOperand(value=raw.get("value", 0), metadata=md)
    if ok == "memory":
        return MemoryOperand(expression=raw.get("expression", ""), metadata=md)
    return UnknownOperand(raw=raw.get("raw", ""), metadata=md)


def _enc_instruction(ins: Instruction | None) -> Any:
    if ins is None:
        return None
    return {
        "mnemonic": ins.mnemonic,
        "operands": [_enc_operand(o) for o in ins.operands],
        "address": ins.address,
        "metadata": _enc_metadata(ins.metadata),
    }


def _dec_instruction(raw: Any) -> Instruction | None:
    if raw is None:
        return None
    return Instruction(
        mnemonic=raw["mnemonic"],
        operands=tuple(_dec_operand(o) for o in raw.get("operands", [])),
        address=raw.get("address"),
        metadata=_dec_metadata(raw.get("metadata")),
    )


# --- symbols ----------------------------------------------------------------


def _enc_symbol(sym: Symbol | None) -> Any:
    if sym is None:
        return None
    return {
        "name": sym.name,
        "kind": sym.kind.value,
        "visibility": sym.visibility.value,
        "binding": sym.binding.value,
        "metadata": _enc_metadata(sym.metadata),
    }


def _dec_symbol(raw: Any) -> Symbol | None:
    if raw is None:
        return None
    return Symbol(
        name=raw["name"],
        kind=SymbolKind(raw.get("kind", "unknown")),
        visibility=Visibility(raw.get("visibility", "unknown")),
        binding=Binding(raw.get("binding", "unknown")),
        metadata=_dec_metadata(raw.get("metadata")),
    )


# --- nodes ------------------------------------------------------------------


def _enc_node(node: IRNode) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": node.kind.value,
        "id": node.identifier.value,
        "name": node.name,
        "path": list(node.path.segments),
        "metadata": _enc_metadata(node.metadata),
    }
    if isinstance(node, ModuleNode):
        base["architecture"] = node.architecture
        base["file_format"] = node.file_format
    elif isinstance(node, SectionNode):
        base["size"] = node.size
    elif isinstance(node, SegmentNode):
        base["permissions"] = node.permissions
    elif isinstance(node, TypeNode):
        base["ir_type"] = _enc_type(node.ir_type)
    elif isinstance(node, FunctionNode):
        base["signature"] = _enc_type(node.signature)
    elif isinstance(node, MethodNode):
        base["signature"] = _enc_type(node.signature)
        base["owner"] = node.owner
    elif isinstance(node, InstructionNode):
        base["instruction"] = _enc_instruction(node.instruction)
    elif isinstance(node, DataNode):
        base["size"] = node.size
    elif isinstance(node, StringNode):
        base["value"] = node.value
        base["encoding"] = node.encoding
    elif isinstance(node, SymbolNode):
        base["symbol"] = _enc_symbol(node.symbol)
    elif isinstance(node, ImportNode):
        base["symbol_name"] = node.symbol_name
        base["module_name"] = node.module_name
    elif isinstance(node, ExportNode):
        base["symbol_name"] = node.symbol_name
    return base


def _dec_node(raw: Any) -> IRNode:
    kind = NodeKind(raw["kind"])
    common = {
        "identifier": IRIdentifier(raw["id"]),
        "name": raw["name"],
        "path": IRPath(tuple(raw.get("path", []))),
        "metadata": _dec_metadata(raw.get("metadata")),
    }
    if kind is NodeKind.MODULE:
        return ModuleNode(
            **common, architecture=raw.get("architecture", "unknown"),
            file_format=raw.get("file_format", "unknown"),
        )
    if kind is NodeKind.SECTION:
        return SectionNode(**common, size=raw.get("size", 0))
    if kind is NodeKind.SEGMENT:
        return SegmentNode(**common, permissions=raw.get("permissions", ""))
    if kind is NodeKind.NAMESPACE:
        return NamespaceNode(**common)
    if kind is NodeKind.TYPE:
        return TypeNode(**common, ir_type=_dec_type(raw.get("ir_type")))
    if kind is NodeKind.CLASS:
        return ClassNode(**common)
    if kind is NodeKind.FUNCTION:
        sig = _dec_type(raw.get("signature"))
        return FunctionNode(**common, signature=sig if isinstance(sig, FunctionSignature) else None)
    if kind is NodeKind.METHOD:
        sig = _dec_type(raw.get("signature"))
        return MethodNode(
            **common,
            signature=sig if isinstance(sig, FunctionSignature) else None,
            owner=raw.get("owner", ""),
        )
    if kind is NodeKind.BASIC_BLOCK:
        return BasicBlockNode(**common)
    if kind is NodeKind.INSTRUCTION:
        return InstructionNode(**common, instruction=_dec_instruction(raw.get("instruction")))
    if kind is NodeKind.DATA:
        return DataNode(**common, size=raw.get("size", 0))
    if kind is NodeKind.STRING:
        return StringNode(**common, value=raw.get("value", ""), encoding=raw.get("encoding", "utf-8"))
    if kind is NodeKind.SYMBOL:
        return SymbolNode(**common, symbol=_dec_symbol(raw.get("symbol")))
    if kind is NodeKind.IMPORT:
        return ImportNode(
            **common, symbol_name=raw.get("symbol_name", ""), module_name=raw.get("module_name", "")
        )
    if kind is NodeKind.EXPORT:
        return ExportNode(**common, symbol_name=raw.get("symbol_name", ""))
    raise SerializationError("unknown node kind", kind=raw["kind"])


# --- edges ------------------------------------------------------------------


def _enc_edge(edge: IREdge) -> dict[str, Any]:
    return {
        "kind": edge.kind.value,
        "source": edge.source.value,
        "target": edge.target.value,
        "metadata": _enc_metadata(edge.metadata),
    }


def _dec_edge(raw: Any) -> IREdge:
    return IREdge(
        kind=EdgeKind(raw["kind"]),
        source=IRIdentifier(raw["source"]),
        target=IRIdentifier(raw["target"]),
        metadata=_dec_metadata(raw.get("metadata")),
    )


class IRSerializer:
    """Serializes an ``IRModule`` to canonical JSON text."""

    def serialize(self, module: IRModule) -> str:
        nodes = sorted((_enc_node(n) for n in module.nodes), key=lambda d: d["id"])
        edges = sorted(
            (_enc_edge(e) for e in module.edges),
            key=lambda d: (d["kind"], d["source"], d["target"]),
        )
        payload = {"root": module.root.value, "nodes": nodes, "edges": edges}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class IRDeserializer:
    """Reconstructs an ``IRModule`` from canonical JSON text."""

    def deserialize(self, data: str) -> IRModule:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid IR document", detail=str(exc)) from exc
        nodes = tuple(_dec_node(n) for n in payload.get("nodes", []))
        edges = tuple(_dec_edge(e) for e in payload.get("edges", []))
        return IRModule(root=IRIdentifier(payload["root"]), nodes=nodes, edges=edges)
