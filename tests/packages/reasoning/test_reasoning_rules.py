"""Reasoning tests: each reference rule fires on a crafted graph and stays silent otherwise."""

from __future__ import annotations

from _reasoning_helpers import build_sample, build_sample_graph, build_sample_repository
from reveng_reasoning import RuleContext
from reveng_reasoning.reference import (
    DeadSectionRule,
    DuplicateEvidenceRule,
    DuplicateSymbolRule,
    ImportedButNotReferencedRule,
    MissingEntrySymbolRule,
    UnusedFunctionRule,
)
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceKind,
    EvidenceRepository,
    build_evidence,
)


def _ctx():
    graph, repo = build_sample()
    return RuleContext(graph=graph, evidence=repo)


def test_dead_section_fires() -> None:
    result = DeadSectionRule().apply(_ctx())
    assert len(result.inferences) == 1
    assert result.inferences[0].fact.startswith("dead section")


def test_duplicate_symbol_fires() -> None:
    result = DuplicateSymbolRule().apply(_ctx())
    assert len(result.inferences) == 1
    inf = result.inferences[0]
    assert inf.fact == "duplicate symbol: dup"
    # Explanation cites exactly the two symbol node ids.
    assert len(inf.explanation.input_nodes) == 2


def test_imported_but_not_referenced_fires() -> None:
    result = ImportedButNotReferencedRule().apply(_ctx())
    assert any("printf" in i.fact for i in result.inferences)


def test_missing_entry_symbol_fires() -> None:
    result = MissingEntrySymbolRule().apply(_ctx())
    assert len(result.inferences) == 1
    assert result.inferences[0].fact.startswith("missing entry symbol")


def test_missing_entry_symbol_silent_when_entry_present() -> None:
    # A module containing a 'main' symbol should not fire.
    from reveng_intermediate_representation import IRBuilder, Symbol, SymbolKind
    from reveng_knowledge_graph import KnowledgeGraphBuilder

    mb = IRBuilder().module("app", architecture="x86_64", file_format="elf")
    mb.add_symbol(Symbol(name="main", kind=SymbolKind.UNKNOWN))
    ir = mb.build()
    graph = KnowledgeGraphBuilder().build(ir, ())
    ctx = RuleContext(graph=graph, evidence=build_sample_repository(ir))
    assert MissingEntrySymbolRule().apply(ctx).inferences == ()


def test_unused_function_silent_without_functions() -> None:
    # The sample graph has no FUNCTION nodes -> rule returns nothing.
    result = UnusedFunctionRule().apply(_ctx())
    assert result.inferences == ()


def test_duplicate_evidence_fires() -> None:
    graph = build_sample_graph()
    repo = EvidenceRepository()
    # Two evidence records asserting the same (kind, refs, artifact).
    for key in ("a", "b"):
        repo.add(
            build_evidence(
                key=key,
                kind=EvidenceKind.ARTIFACT,
                confidence=EvidenceConfidence.OBSERVED,
                artifact_ref="X",
            )
        )
    result = DuplicateEvidenceRule().apply(RuleContext(graph=graph, evidence=repo))
    assert len(result.inferences) == 1
    assert len(result.inferences[0].explanation.input_evidence) == 2


def test_rule_is_deterministic() -> None:
    ctx = _ctx()
    a = DuplicateSymbolRule().apply(ctx)
    b = DuplicateSymbolRule().apply(ctx)
    assert [i.id.value for i in a.inferences] == [i.id.value for i in b.inferences]
