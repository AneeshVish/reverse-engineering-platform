"""Shared builders for investigation tests.

Builds a full upstream pipeline (IR -> knowledge graph + evidence -> reasoning
result) shaped to produce several findings.
"""

from __future__ import annotations

from reveng_intermediate_representation import IRBuilder, IRModule, Symbol, SymbolKind
from reveng_knowledge_graph import KnowledgeGraph, KnowledgeGraphBuilder
from reveng_reasoning import (
    ReasoningEngine,
    ReasoningResult,
    RuleRegistry,
    register_builtin_rules,
)
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceKind,
    EvidenceRepository,
    build_evidence,
)


def build_ir(name: str = "libfoo") -> IRModule:
    mb = IRBuilder().module(name, architecture="x86_64", file_format="elf")
    mb.add_section(".text", size=100)  # empty -> dead_section
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.UNKNOWN))
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.FUNCTION))  # duplicate name
    mb.add_symbol(Symbol(name="printf", kind=SymbolKind.IMPORT))  # unreferenced import
    return mb.build()


def build_pipeline() -> tuple[KnowledgeGraph, EvidenceRepository, ReasoningResult]:
    ir = build_ir()
    graph = KnowledgeGraphBuilder().build(ir, ())
    repo = EvidenceRepository()
    repo.add(
        build_evidence(
            key="e1",
            kind=EvidenceKind.IR_MODULE,
            confidence=EvidenceConfidence.EXTRACTED,
            ir_refs=(ir.root,),
            artifact_ref="art1",
        )
    )
    reg = RuleRegistry()
    register_builtin_rules(reg)
    reasoning = ReasoningEngine().run(reg, graph, repo)
    return graph, repo, reasoning
