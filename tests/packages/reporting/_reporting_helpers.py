"""Shared builders for reporting tests.

Builds the full upstream pipeline (IR -> graph + evidence -> reasoning -> case)
so reports can be projected from a real investigation case.
"""

from __future__ import annotations

from reveng_intermediate_representation import IRBuilder, Symbol, SymbolKind
from reveng_investigation import InvestigationBuilder, InvestigationCase
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


def build_pipeline() -> tuple[
    InvestigationCase, ReasoningResult, EvidenceRepository, KnowledgeGraph
]:
    mb = IRBuilder().module("libfoo", architecture="x86_64", file_format="elf")
    mb.add_section(".text", size=100)
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.UNKNOWN))
    mb.add_symbol(Symbol(name="dup", kind=SymbolKind.FUNCTION))
    mb.add_symbol(Symbol(name="printf", kind=SymbolKind.IMPORT))
    ir = mb.build()

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
    case = InvestigationBuilder().build(graph, repo, reasoning)
    return case, reasoning, repo, graph


def valid_ids(case, reasoning, repo, graph) -> set[str]:
    ids: set[str] = set()
    ids.update(f.id.value for f in case.findings)
    ids.update(i.id.value for i in reasoning.inferences)
    ids.update(e.id.value for e in repo.enumerate())
    ids.update(n.id.value for n in graph.nodes)
    ids.update(e.id.value for e in graph.edges)
    return ids
