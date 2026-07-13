"""Static-analysis tests: IR builder and evidence builder."""

from __future__ import annotations

from _static_helpers import make_artifact
from reveng_intermediate_representation import NodeKind, SymbolKind, SymbolNode
from reveng_static_analysis import (
    EvidenceBuilder,
    ExtractedExport,
    ExtractedImport,
    ExtractedSection,
    ExtractedSymbol,
    ExtractionResult,
    IRArtifactBuilder,
)
from reveng_storage_evidence import EvidenceConfidence, EvidenceKind


def _extraction() -> ExtractionResult:
    return ExtractionResult(
        sections=(ExtractedSection(name=".text", size=100),),
        symbols=(ExtractedSymbol(name="main"),),
        imports=(ExtractedImport(name="printf", module="libc"),),
        exports=(ExtractedExport(name="run"),),
    )


def test_ir_builder_maps_entities_to_nodes() -> None:
    art = make_artifact()
    result = IRArtifactBuilder().build(art, _extraction())
    kinds = {n.kind for n in result.module.nodes}
    assert NodeKind.MODULE in kinds
    assert NodeKind.SECTION in kinds
    assert NodeKind.SYMBOL in kinds
    # section + symbol + import + export are represented as nodes.
    assert len(result.node_ids) == 4


def test_imports_exports_are_symbols() -> None:
    art = make_artifact()
    result = IRArtifactBuilder().build(art, _extraction())
    sym_kinds = {
        n.symbol.kind
        for n in result.module.nodes
        if isinstance(n, SymbolNode) and n.symbol is not None
    }
    assert SymbolKind.IMPORT in sym_kinds
    assert SymbolKind.EXPORT in sym_kinds


def test_ir_module_name_derives_from_content_hash() -> None:
    art = make_artifact()
    result = IRArtifactBuilder().build(art, ExtractionResult())
    root = result.module.node_by_id(result.module.root)
    assert root is not None
    assert art.identity.content_hash in root.name


def test_ir_builder_is_deterministic() -> None:
    art = make_artifact()
    a = IRArtifactBuilder().build(art, _extraction())
    b = IRArtifactBuilder().build(art, _extraction())
    assert a.module.root == b.module.root
    assert {n.identifier for n in a.module.nodes} == {n.identifier for n in b.module.nodes}


def test_evidence_builder_links_nodes_and_uses_tiers() -> None:
    art = make_artifact()
    ir = IRArtifactBuilder().build(art, _extraction())
    evidence = EvidenceBuilder().build(art, _extraction(), ir)
    # Node-linked evidence carries EXTRACTED confidence; anchor is OBSERVED.
    node_ev = [e for e in evidence if e.kind is EvidenceKind.IR_NODE]
    assert node_ev and all(e.confidence is EvidenceConfidence.EXTRACTED for e in node_ev)
    assert all(len(e.ir_refs) == 1 for e in node_ev)
    anchor = [e for e in evidence if e.kind is EvidenceKind.ARTIFACT]
    assert anchor and anchor[0].confidence is EvidenceConfidence.OBSERVED


def test_evidence_keys_deterministic() -> None:
    art = make_artifact()
    ir = IRArtifactBuilder().build(art, _extraction())
    a = EvidenceBuilder().build(art, _extraction(), ir)
    b = EvidenceBuilder().build(art, _extraction(), ir)
    assert [e.id.value for e in a] == [e.id.value for e in b]


def test_evidence_artifact_ref_is_content_hash() -> None:
    art = make_artifact()
    ir = IRArtifactBuilder().build(art, ExtractionResult())
    evidence = EvidenceBuilder().build(art, ExtractionResult(), ir)
    assert all(e.artifact_ref == art.identity.content_hash for e in evidence)
