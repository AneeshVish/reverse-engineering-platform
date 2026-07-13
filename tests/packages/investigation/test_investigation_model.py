"""Investigation tests: finding/case/chain/timeline model and immutability."""

from __future__ import annotations

import dataclasses

import pytest
from _investigation_helpers import build_pipeline
from reveng_investigation import (
    CaseID,
    Finding,
    FindingID,
    FindingKind,
    FindingSeverity,
    InvestigationBuilder,
    build_finding,
    build_timeline,
    chains_for,
)


def test_finding_id_is_content_derived() -> None:
    a = FindingID.of(FindingKind.DEAD_CODE, "s", ("i1", "i2"))
    b = FindingID.of(FindingKind.DEAD_CODE, "s", ("i2", "i1"))  # order-independent
    assert a == b
    assert a.value != FindingID.of(FindingKind.DEAD_CODE, "s", ("i3",)).value


def test_finding_id_is_sha256_hex() -> None:
    v = FindingID.of(FindingKind.DEAD_CODE, "s", ("i",)).value
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_case_id_order_independent() -> None:
    assert CaseID.of(("a", "b")) == CaseID.of(("b", "a"))


def test_build_finding_records_explanation() -> None:
    f = build_finding(
        kind=FindingKind.REFERENCE_INTEGRITY,
        severity=FindingSeverity.MEDIUM,
        subject="node1",
        title="a title",
        inference_ids=("i1",),
        evidence_ids=("e1",),
        node_ids=("n1",),
        edge_ids=("g1",),
    )
    assert f.explanation.inference_ids == ("i1",)
    assert f.explanation.evidence_ids == ("e1",)
    assert f.explanation.node_ids == ("n1",)
    assert f.explanation.edge_ids == ("g1",)


def test_finding_is_immutable() -> None:
    f = build_finding(
        kind=FindingKind.DEAD_CODE,
        severity=FindingSeverity.LOW,
        subject="s",
        title="t",
    )
    assert isinstance(f, Finding)
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.title = "x"  # type: ignore[misc]


def test_chains_for_finding() -> None:
    f = build_finding(
        kind=FindingKind.DEAD_CODE,
        severity=FindingSeverity.LOW,
        subject="s",
        title="t",
        inference_ids=("i1",),
        evidence_ids=("e1",),
        node_ids=("n1",),
        edge_ids=("g1",),
    )
    inference_chain, evidence_chain, graph_chain = chains_for(f)
    assert inference_chain.inference_ids == ("i1",)
    assert evidence_chain.evidence_ids == ("e1",)
    assert graph_chain.node_ids == ("n1",)
    assert graph_chain.edge_ids == ("g1",)


def test_timeline_is_deterministic() -> None:
    graph, repo, reasoning = build_pipeline()
    case = InvestigationBuilder().build(graph, repo, reasoning)
    a = build_timeline(case).ordered()
    b = build_timeline(case).ordered()
    assert [f.id.value for f in a] == [f.id.value for f in b]
    assert len(a) == len(case.findings)


def test_finding_severities_are_labels_not_scores() -> None:
    assert {s.value for s in FindingSeverity} == {"info", "low", "medium", "high", "critical"}
