"""Protocol definitions later packages implement.

These describe how future packages provide, consume, and build graphs. They are
protocols only — the concrete builder is ``KnowledgeGraphBuilder``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reveng_intermediate_representation import IRModule
from reveng_storage_evidence import Evidence

from .graph import KnowledgeGraph

__all__ = ["GraphProvider", "GraphConsumer", "GraphBuilder"]


@runtime_checkable
class GraphProvider(Protocol):
    """Produces a ``KnowledgeGraph`` (implemented by later packages)."""

    def provide(self) -> KnowledgeGraph: ...


@runtime_checkable
class GraphConsumer(Protocol):
    """Consumes a ``KnowledgeGraph`` (implemented by later packages)."""

    def consume(self, graph: KnowledgeGraph) -> None: ...


@runtime_checkable
class GraphBuilder(Protocol):
    """Builds a ``KnowledgeGraph`` from IR and evidence."""

    def build(self, ir_module: IRModule, evidence: tuple[Evidence, ...]) -> KnowledgeGraph: ...
