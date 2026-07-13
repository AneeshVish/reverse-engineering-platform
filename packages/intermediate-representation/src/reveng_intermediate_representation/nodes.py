"""Canonical node hierarchy and the immutable module container.

Nodes are flat, immutable records identified by a content-derived
``IRIdentifier``. Containment and other relationships are expressed with
``IREdge``s, not by embedding child objects — so the model has no mutable graph
and no in-place edits. An ``IRModule`` is the immutable collection of nodes and
edges that make up one program representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .edges import EdgeKind, IREdge
from .identity import IRIdentifier, IRPath
from .instructions import Instruction
from .metadata import EMPTY_METADATA, MetadataBag
from .symbols import Symbol
from .types import FunctionSignature, IRType

__all__ = [
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
]


class NodeKind(str, Enum):
    MODULE = "module"
    SECTION = "section"
    SEGMENT = "segment"
    NAMESPACE = "namespace"
    TYPE = "type"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    BASIC_BLOCK = "basic_block"
    INSTRUCTION = "instruction"
    DATA = "data"
    STRING = "string"
    SYMBOL = "symbol"
    IMPORT = "import"
    EXPORT = "export"


@dataclass(frozen=True, kw_only=True)
class IRNode:
    """Base of the immutable node hierarchy."""

    identifier: IRIdentifier
    kind: NodeKind
    name: str
    path: IRPath
    metadata: MetadataBag = EMPTY_METADATA


@dataclass(frozen=True, kw_only=True)
class ModuleNode(IRNode):
    kind: NodeKind = NodeKind.MODULE
    architecture: str = "unknown"
    file_format: str = "unknown"


@dataclass(frozen=True, kw_only=True)
class SectionNode(IRNode):
    kind: NodeKind = NodeKind.SECTION
    size: int = 0


@dataclass(frozen=True, kw_only=True)
class SegmentNode(IRNode):
    kind: NodeKind = NodeKind.SEGMENT
    permissions: str = ""


@dataclass(frozen=True, kw_only=True)
class NamespaceNode(IRNode):
    kind: NodeKind = NodeKind.NAMESPACE


@dataclass(frozen=True, kw_only=True)
class TypeNode(IRNode):
    kind: NodeKind = NodeKind.TYPE
    ir_type: IRType | None = None


@dataclass(frozen=True, kw_only=True)
class ClassNode(IRNode):
    kind: NodeKind = NodeKind.CLASS


@dataclass(frozen=True, kw_only=True)
class FunctionNode(IRNode):
    kind: NodeKind = NodeKind.FUNCTION
    signature: FunctionSignature | None = None


@dataclass(frozen=True, kw_only=True)
class MethodNode(IRNode):
    kind: NodeKind = NodeKind.METHOD
    signature: FunctionSignature | None = None
    owner: str = ""


@dataclass(frozen=True, kw_only=True)
class BasicBlockNode(IRNode):
    kind: NodeKind = NodeKind.BASIC_BLOCK


@dataclass(frozen=True, kw_only=True)
class InstructionNode(IRNode):
    kind: NodeKind = NodeKind.INSTRUCTION
    instruction: Instruction | None = None


@dataclass(frozen=True, kw_only=True)
class DataNode(IRNode):
    kind: NodeKind = NodeKind.DATA
    size: int = 0


@dataclass(frozen=True, kw_only=True)
class StringNode(IRNode):
    kind: NodeKind = NodeKind.STRING
    value: str = ""
    encoding: str = "utf-8"


@dataclass(frozen=True, kw_only=True)
class SymbolNode(IRNode):
    kind: NodeKind = NodeKind.SYMBOL
    symbol: Symbol | None = None


@dataclass(frozen=True, kw_only=True)
class ImportNode(IRNode):
    kind: NodeKind = NodeKind.IMPORT
    symbol_name: str = ""
    module_name: str = ""


@dataclass(frozen=True, kw_only=True)
class ExportNode(IRNode):
    kind: NodeKind = NodeKind.EXPORT
    symbol_name: str = ""


@dataclass(frozen=True)
class IRModule:
    """An immutable collection of nodes and edges — one program representation."""

    root: IRIdentifier
    nodes: tuple[IRNode, ...] = field(default_factory=tuple)
    edges: tuple[IREdge, ...] = field(default_factory=tuple)

    def node_by_id(self, identifier: IRIdentifier) -> IRNode | None:
        for node in self.nodes:
            if node.identifier == identifier:
                return node
        return None

    def node_ids(self) -> frozenset[IRIdentifier]:
        return frozenset(node.identifier for node in self.nodes)

    def nodes_of_kind(self, kind: NodeKind) -> tuple[IRNode, ...]:
        return tuple(node for node in self.nodes if node.kind is kind)

    def edges_of_kind(self, kind: EdgeKind) -> tuple[IREdge, ...]:
        return tuple(edge for edge in self.edges if edge.kind is kind)

    def __len__(self) -> int:
        return len(self.nodes)
