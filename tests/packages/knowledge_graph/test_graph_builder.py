"""Knowledge-graph tests: the builder from IR + Evidence."""

from __future__ import annotations

from _graph_helpers import ARTIFACT_REF, build_sample, build_sample_ir
from reveng_knowledge_graph import (
    GraphNodeKind,
    KnowledgeGraphBuilder,
    RelationshipKind,
)


def _build():
    ir, ev = build_sample()
    return KnowledgeGraphBuilder().build(ir, ev)


def test_builder_produces_expected_node_kinds() -> None:
    graph = _build()
    kinds = {n.kind for n in graph.nodes}
    assert GraphNodeKind.MODULE in kinds
    assert GraphNodeKind.SECTION in kinds
    assert GraphNodeKind.SYMBOL in kinds
    assert GraphNodeKind.EVIDENCE in kinds
    assert GraphNodeKind.ARTIFACT in kinds


def test_builder_produces_contains_edges() -> None:
    graph = _build()
    contains = graph.edges_of_kind(RelationshipKind.CONTAINS)
    # module contains section + 3 symbols
    assert len(contains) == 4


def test_builder_produces_import_export_edges() -> None:
    graph = _build()
    assert len(graph.edges_of_kind(RelationshipKind.IMPORTS)) == 1
    assert len(graph.edges_of_kind(RelationshipKind.EXPORTS)) == 1


def test_builder_produces_observed_in_and_derived_from() -> None:
    graph = _build()
    assert len(graph.edges_of_kind(RelationshipKind.OBSERVED_IN)) == 1  # module observed in e1
    assert len(graph.edges_of_kind(RelationshipKind.DERIVED_FROM)) == 2  # e1,e2 -> artifact


def test_artifact_node_deduplicated() -> None:
    graph = _build()
    artifacts = graph.nodes_of_kind(GraphNodeKind.ARTIFACT)
    assert len(artifacts) == 1
    assert artifacts[0].logical_key == ARTIFACT_REF


def test_node_ids_derive_from_ir_identity() -> None:
    ir, ev = build_sample()
    graph = KnowledgeGraphBuilder().build(ir, ev)
    module_node = graph.nodes_of_kind(GraphNodeKind.MODULE)[0]
    assert module_node.logical_key == ir.root.value


def test_builder_is_deterministic() -> None:
    ir, ev = build_sample()
    a = KnowledgeGraphBuilder().build(ir, ev)
    b = KnowledgeGraphBuilder().build(ir, ev)
    assert {n.id.value for n in a.nodes} == {n.id.value for n in b.nodes}
    assert {e.id.value for e in a.edges} == {e.id.value for e in b.edges}


def test_nodes_and_edges_sorted_by_id() -> None:
    graph = _build()
    node_ids = [n.id.value for n in graph.nodes]
    edge_ids = [e.id.value for e in graph.edges]
    assert node_ids == sorted(node_ids)
    assert edge_ids == sorted(edge_ids)


def test_build_without_evidence() -> None:
    ir = build_sample_ir()
    graph = KnowledgeGraphBuilder().build(ir)
    # IR-only: module/section/symbol nodes, no evidence/artifact nodes.
    assert not graph.nodes_of_kind(GraphNodeKind.EVIDENCE)
    assert not graph.nodes_of_kind(GraphNodeKind.ARTIFACT)
    assert graph.nodes_of_kind(GraphNodeKind.MODULE)


def test_builder_does_not_mutate_inputs() -> None:
    ir, ev = build_sample()
    before_nodes = len(ir.nodes)
    KnowledgeGraphBuilder().build(ir, ev)
    assert len(ir.nodes) == before_nodes
