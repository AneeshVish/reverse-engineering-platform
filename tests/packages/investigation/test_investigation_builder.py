"""Investigation tests: case construction from the analysis pipeline."""

from __future__ import annotations

from _investigation_helpers import build_pipeline
from reveng_investigation import (
    CasePriority,
    CaseStatus,
    FindingKind,
    InvestigationBuilder,
)


def _case():
    graph, repo, reasoning = build_pipeline()
    return InvestigationBuilder().build(graph, repo, reasoning)


def test_builder_produces_findings() -> None:
    case = _case()
    kinds = {f.kind for f in case.findings}
    assert FindingKind.DEAD_CODE in kinds
    assert FindingKind.DUPLICATE_SYMBOL in kinds
    assert FindingKind.MISSING_ENTRY in kinds


def test_case_status_and_priority() -> None:
    case = _case()
    assert case.status is CaseStatus.OPEN
    # missing_entry / unresolved_import contribute HIGH severity -> HIGH priority.
    assert case.priority is CasePriority.HIGH


def test_findings_sorted_by_id() -> None:
    case = _case()
    ids = [f.id.value for f in case.findings]
    assert ids == sorted(ids)


def test_case_id_derives_from_inference_ids() -> None:
    from reveng_investigation import CaseID

    case = _case()
    assert case.id == CaseID.of(case.inference_ids())


def test_deterministic_repeated_builds() -> None:
    graph, repo, reasoning = build_pipeline()
    a = InvestigationBuilder().build(graph, repo, reasoning)
    b = InvestigationBuilder().build(graph, repo, reasoning)
    assert a.id == b.id
    assert [f.id.value for f in a.findings] == [f.id.value for f in b.findings]


def test_finding_traces_to_inference() -> None:
    graph, repo, reasoning = build_pipeline()
    inference_ids = {i.id.value for i in reasoning.inferences}
    case = InvestigationBuilder().build(graph, repo, reasoning)
    for finding in case.findings:
        assert finding.explanation.inference_ids
        for inf in finding.explanation.inference_ids:
            assert inf in inference_ids


def test_builder_does_not_mutate_inputs() -> None:
    graph, repo, reasoning = build_pipeline()
    before_nodes = len(graph.nodes)
    before_ev = len(repo)
    before_inf = len(reasoning)
    InvestigationBuilder().build(graph, repo, reasoning)
    assert len(graph.nodes) == before_nodes
    assert len(repo) == before_ev
    assert len(reasoning) == before_inf


def test_empty_reasoning_yields_low_priority_case() -> None:
    from reveng_reasoning import ReasoningResult

    graph, repo, _ = build_pipeline()
    case = InvestigationBuilder().build(graph, repo, ReasoningResult(()))
    assert len(case) == 0
    assert case.priority is CasePriority.LOW
