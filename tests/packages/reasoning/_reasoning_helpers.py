"""Shared builders for reasoning tests.

Builds a small KnowledgeGraph + EvidenceRepository shaped to trigger specific
reference rules.
"""

from __future__ import annotations

from reveng_intermediate_representation import IRBuilder, IRModule, Symbol, SymbolKind
from reveng_knowledge_graph import KnowledgeGraph, KnowledgeGraphBuilder
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceKind,
    EvidenceRepository,
    build_evidence,
)


def build_sample_ir(name: str = "libfoo") -> IRModule:
    mb = IRBuilder().module(name, architecture="x86_64", file_format="elf")
    mb.add_section(".text", size=100)  # empty section -> dead_section
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.UNKNOWN))
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.FUNCTION))  # duplicate name
    mb.add_symbol(Symbol(name="printf", kind=SymbolKind.IMPORT))  # import, unreferenced
    return mb.build()


def build_sample_graph(name: str = "libfoo") -> KnowledgeGraph:
    return KnowledgeGraphBuilder().build(build_sample_ir(name), ())


def build_sample_repository(ir: IRModule | None = None) -> EvidenceRepository:
    module = ir or build_sample_ir()
    repo = EvidenceRepository()
    repo.add(
        build_evidence(
            key="e1",
            kind=EvidenceKind.IR_MODULE,
            confidence=EvidenceConfidence.EXTRACTED,
            ir_refs=(module.root,),
            artifact_ref="art1",
        )
    )
    return repo


def build_sample() -> tuple[KnowledgeGraph, EvidenceRepository]:
    ir = build_sample_ir()
    return KnowledgeGraphBuilder().build(ir, ()), build_sample_repository(ir)
