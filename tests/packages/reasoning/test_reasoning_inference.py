"""Reasoning tests: inference model, explanation chains, immutability."""

from __future__ import annotations

import dataclasses

import pytest
from reveng_reasoning import (
    Inference,
    InferenceID,
    InferenceKind,
    InferenceState,
    build_inference,
)


def test_inference_id_is_content_derived() -> None:
    a = InferenceID.of("rule", "subj", "fact", "inputs")
    b = InferenceID.of("rule", "subj", "fact", "inputs")
    assert a == b
    assert a.value != InferenceID.of("rule", "subj", "fact", "other").value


def test_inference_id_is_sha256_hex() -> None:
    v = InferenceID.of("r", "s", "f", "i").value
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_build_inference_records_full_chain() -> None:
    inf = build_inference(
        rule_id="my_rule",
        kind=InferenceKind.STRUCTURAL,
        subject="node1",
        fact="something",
        input_evidence=("e1",),
        input_nodes=("node1", "node2"),
        input_edges=("edge1",),
    )
    assert inf.explanation.rule_id == "my_rule"
    assert inf.explanation.output_fact == "something"
    assert inf.explanation.input_evidence == ("e1",)
    assert inf.explanation.input_nodes == ("node1", "node2")
    assert inf.explanation.input_edges == ("edge1",)
    assert inf.state is InferenceState.DERIVED


def _infer(input_nodes: tuple[str, ...]) -> Inference:
    return build_inference(
        rule_id="r",
        kind=InferenceKind.STRUCTURAL,
        subject="s",
        fact="f",
        input_nodes=input_nodes,
    )


def test_build_inference_is_deterministic() -> None:
    assert _infer(("a", "b")).id == _infer(("a", "b")).id


def test_inference_id_independent_of_input_order() -> None:
    # explanation.canonical sorts inputs, so order does not affect identity.
    assert _infer(("a", "b")).id == _infer(("b", "a")).id


def test_inference_is_immutable() -> None:
    inf = build_inference(rule_id="r", kind=InferenceKind.STRUCTURAL, subject="s", fact="f")
    with pytest.raises(dataclasses.FrozenInstanceError):
        inf.fact = "x"  # type: ignore[misc]


def test_inference_kinds() -> None:
    assert {k.value for k in InferenceKind} == {
        "structural",
        "reference",
        "duplication",
        "completeness",
        "provenance",
    }


def test_inference_type() -> None:
    inf = build_inference(rule_id="r", kind=InferenceKind.STRUCTURAL, subject="s", fact="f")
    assert isinstance(inf, Inference)
