"""Investigation tests: case validation failures."""

from __future__ import annotations

import dataclasses

import pytest
from _investigation_helpers import build_pipeline
from reveng_investigation import (
    CasePriority,
    CaseStatus,
    FindingKind,
    FindingSeverity,
    InvestigationBuilder,
    InvestigationCase,
    ValidationError,
    build_finding,
    validate_case,
)
from reveng_investigation.case import CaseID


def test_valid_case_passes() -> None:
    graph, repo, reasoning = build_pipeline()
    case = InvestigationBuilder().build(graph, repo, reasoning)
    validate_case(case, graph, repo, reasoning)  # no raise


def _bad_case(**explanation) -> InvestigationCase:
    finding = build_finding(
        kind=FindingKind.DEAD_CODE,
        severity=FindingSeverity.LOW,
        subject="s",
        title="t",
        **explanation,
    )
    return InvestigationCase(
        id=CaseID.of(()),
        status=CaseStatus.OPEN,
        priority=CasePriority.LOW,
        title="c",
        findings=(finding,),
    )


def test_dangling_inference_rejected() -> None:
    graph, repo, reasoning = build_pipeline()
    with pytest.raises(ValidationError):
        validate_case(_bad_case(inference_ids=("ghost",)), graph, repo, reasoning)


def test_dangling_evidence_rejected() -> None:
    graph, repo, reasoning = build_pipeline()
    with pytest.raises(ValidationError):
        validate_case(_bad_case(evidence_ids=("ghost",)), graph, repo, reasoning)


def test_dangling_node_rejected() -> None:
    graph, repo, reasoning = build_pipeline()
    with pytest.raises(ValidationError):
        validate_case(_bad_case(node_ids=("ghost",)), graph, repo, reasoning)


def test_duplicate_finding_rejected() -> None:
    graph, repo, reasoning = build_pipeline()
    case = InvestigationBuilder().build(graph, repo, reasoning)
    dup = dataclasses.replace(case, findings=(case.findings[0], case.findings[0]))
    with pytest.raises(ValidationError):
        validate_case(dup, graph, repo, reasoning)
