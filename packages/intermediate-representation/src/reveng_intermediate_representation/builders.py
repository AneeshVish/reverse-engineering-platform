"""Builders — the only construction path for IR.

Callers assemble IR through builders, never by touching frozen node/edge objects
directly. Builders compute deterministic identities from the hierarchical path,
emit ``Contains`` edges for parent/child relationships, and validate the result
before returning an immutable ``IRModule``. Builders perform no analysis.
"""

from __future__ import annotations

from .edges import EdgeKind, IREdge
from .errors import ConstructionError
from .identity import IRIdentifier, IRPath, derive_identifier
from .instructions import Instruction
from .metadata import EMPTY_METADATA, MetadataBag
from .nodes import (
    BasicBlockNode,
    FunctionNode,
    InstructionNode,
    IRModule,
    IRNode,
    ModuleNode,
    NodeKind,
    SectionNode,
)
from .symbols import Symbol
from .types import FunctionSignature
from .validation import validate_module

__all__ = ["IRBuilder", "ModuleBuilder", "FunctionBuilder", "InstructionBuilder"]


class _Accumulator:
    """Shared collection of nodes and edges being assembled."""

    def __init__(self) -> None:
        self.nodes: list[IRNode] = []
        self.edges: list[IREdge] = []
        self._ids: set[IRIdentifier] = set()

    def add_node(self, node: IRNode) -> None:
        if node.identifier in self._ids:
            raise ConstructionError("duplicate node", node=node.identifier.value)
        self._ids.add(node.identifier)
        self.nodes.append(node)

    def contains(self, parent: IRIdentifier, child: IRIdentifier) -> None:
        self.edges.append(IREdge(kind=EdgeKind.CONTAINS, source=parent, target=child))


class InstructionBuilder:
    """Builds a single instruction node under a basic block."""

    def __init__(self, acc: _Accumulator, parent_path: IRPath, parent_id: IRIdentifier) -> None:
        self._acc = acc
        self._parent_path = parent_path
        self._parent_id = parent_id

    def build(self, index: int, instruction: Instruction) -> IRIdentifier:
        if not instruction.mnemonic:
            raise ConstructionError("instruction requires a mnemonic")
        name = f"{index}:{instruction.mnemonic}"
        path = self._parent_path.child(name)
        content = f"{instruction.mnemonic}|{len(instruction.operands)}"
        node = InstructionNode(
            identifier=derive_identifier(NodeKind.INSTRUCTION.value, path, content),
            name=name,
            path=path,
            instruction=instruction,
        )
        self._acc.add_node(node)
        self._acc.contains(self._parent_id, node.identifier)
        return node.identifier


class FunctionBuilder:
    """Builds a function and its basic blocks / instructions."""

    def __init__(
        self,
        acc: _Accumulator,
        module_path: IRPath,
        module_id: IRIdentifier,
        name: str,
        signature: FunctionSignature | None,
    ) -> None:
        if not name:
            raise ConstructionError("function requires a name")
        self._acc = acc
        self._path = module_path.child(name)
        content = signature.name if signature else ""
        self._node = FunctionNode(
            identifier=derive_identifier(NodeKind.FUNCTION.value, self._path, content),
            name=name,
            path=self._path,
            signature=signature,
        )
        acc.add_node(self._node)
        acc.contains(module_id, self._node.identifier)
        self._block_count = 0

    @property
    def identifier(self) -> IRIdentifier:
        return self._node.identifier

    def add_basic_block(self, label: str | None = None) -> IRIdentifier:
        name = label or f"block{self._block_count}"
        self._block_count += 1
        path = self._path.child(name)
        node = BasicBlockNode(
            identifier=derive_identifier(NodeKind.BASIC_BLOCK.value, path, name),
            name=name,
            path=path,
        )
        self._acc.add_node(node)
        self._acc.contains(self._node.identifier, node.identifier)
        return node.identifier

    def instruction_builder(self, block_id: IRIdentifier, block_label: str) -> InstructionBuilder:
        return InstructionBuilder(self._acc, self._path.child(block_label), block_id)


class ModuleBuilder:
    """Builds a module and its top-level children."""

    def __init__(self, name: str, *, architecture: str = "unknown", file_format: str = "unknown") -> None:
        if not name:
            raise ConstructionError("module requires a name")
        self._acc = _Accumulator()
        self._path = IRPath.root().child(name)
        self._node = ModuleNode(
            identifier=derive_identifier(NodeKind.MODULE.value, self._path, architecture),
            name=name,
            path=self._path,
            architecture=architecture,
            file_format=file_format,
        )
        self._acc.add_node(self._node)

    @property
    def identifier(self) -> IRIdentifier:
        return self._node.identifier

    def add_section(self, name: str, *, size: int = 0, metadata: MetadataBag = EMPTY_METADATA) -> IRIdentifier:
        if not name:
            raise ConstructionError("section requires a name")
        path = self._path.child(name)
        node = SectionNode(
            identifier=derive_identifier(NodeKind.SECTION.value, path, str(size)),
            name=name,
            path=path,
            size=size,
            metadata=metadata,
        )
        self._acc.add_node(node)
        self._acc.contains(self._node.identifier, node.identifier)
        return node.identifier

    def add_symbol(self, symbol: Symbol) -> IRIdentifier:
        from .nodes import SymbolNode

        if not symbol.name:
            raise ConstructionError("symbol requires a name")
        path = self._path.child(f"sym:{symbol.name}")
        node = SymbolNode(
            identifier=derive_identifier(NodeKind.SYMBOL.value, path, symbol.kind.value),
            name=symbol.name,
            path=path,
            symbol=symbol,
        )
        self._acc.add_node(node)
        self._acc.contains(self._node.identifier, node.identifier)
        return node.identifier

    def function_builder(
        self, name: str, signature: FunctionSignature | None = None
    ) -> FunctionBuilder:
        return FunctionBuilder(self._acc, self._path, self._node.identifier, name, signature)

    def build(self) -> IRModule:
        module = IRModule(
            root=self._node.identifier,
            nodes=tuple(self._acc.nodes),
            edges=tuple(self._acc.edges),
        )
        validate_module(module)
        return module


class IRBuilder:
    """Top-level entry point for constructing IR modules."""

    def module(
        self, name: str, *, architecture: str = "unknown", file_format: str = "unknown"
    ) -> ModuleBuilder:
        return ModuleBuilder(name, architecture=architecture, file_format=file_format)
