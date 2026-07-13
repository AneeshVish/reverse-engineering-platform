"""Reasoning tests: result validation failures."""

from __future__ import annotations

import pytest
from _reasoning_helpers import build_sample
from reveng_reasoning import (
    InferenceKind,
    ReasoningEngine,
    ReasoningResult,
    RuleRegistry,
    ValidationError,
    build_inference,
    register_builtin_rules,
    validate_result,
)


def test_valid_result_passes() -> None:
    reg = RuleRegistry()
    register_builtin_rules(reg)
    graph, repo = build_sample()
    result = ReasoningEngine().run(reg, graph, repo)
    validate_result(result, graph, repo)  # no raise


def test_dangling_node_reference_rejected() -> None:
    graph, repo = build_sample()
    bad = build_inference(
        rule_id="r",
        kind=InferenceKind.STRUCTURAL,
        subject="ghost",
        fact="bad",
        input_nodes=("nonexistent-node",),
    )
    with pytest.raises(ValidationError):
        validate_result(ReasoningResult((bad,)), graph, repo)


def test_missing_evidence_reference_rejected() -> None:
    graph, repo = build_sample()
    bad = build_inference(
        rule_id="r",
        kind=InferenceKind.PROVENANCE,
        subject="s",
        fact="bad",
        input_evidence=("nonexistent-evidence",),
    )
    with pytest.raises(ValidationError):
        validate_result(ReasoningResult((bad,)), graph, repo)


def test_duplicate_inference_id_rejected() -> None:
    graph, repo = build_sample()
    inf = build_inference(rule_id="r", kind=InferenceKind.STRUCTURAL, subject="s", fact="f")
    with pytest.raises(ValidationError):
        validate_result(ReasoningResult((inf, inf)), graph, repo)
