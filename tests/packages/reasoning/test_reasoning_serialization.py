"""Reasoning tests: deterministic serialization, round-trip, and queries."""

from __future__ import annotations

import dataclasses

import pytest
from _reasoning_helpers import build_sample
from reveng_reasoning import (
    InferenceKind,
    ReasoningDeserializer,
    ReasoningEngine,
    ReasoningQuery,
    ReasoningQueryFilter,
    ReasoningSerializer,
    RuleRegistry,
    SerializationError,
    register_builtin_rules,
)


def _result():
    reg = RuleRegistry()
    register_builtin_rules(reg)
    graph, repo = build_sample()
    return ReasoningEngine().run(reg, graph, repo)


def test_serialization_is_deterministic() -> None:
    a = _result()
    b = _result()
    assert ReasoningSerializer().serialize(a) == ReasoningSerializer().serialize(b)


def test_serialization_order_independent() -> None:
    result = _result()
    rev = dataclasses.replace(result, inferences=tuple(reversed(result.inferences)))
    assert ReasoningSerializer().serialize(result) == ReasoningSerializer().serialize(rev)


def test_round_trip_reproduces_equal_result() -> None:
    result = _result()
    data = ReasoningSerializer().serialize(result)
    restored = ReasoningDeserializer().deserialize(data)
    assert ReasoningSerializer().serialize(restored) == data


def test_round_trip_preserves_explanation() -> None:
    result = _result()
    restored = ReasoningDeserializer().deserialize(ReasoningSerializer().serialize(result))
    original = {i.id.value: i for i in result.inferences}
    for inf in restored.inferences:
        assert inf.explanation.rule_id == original[inf.id.value].explanation.rule_id


def test_invalid_document_raises() -> None:
    with pytest.raises(SerializationError):
        ReasoningDeserializer().deserialize("{not json")


def test_no_timestamp_in_output() -> None:
    data = ReasoningSerializer().serialize(_result())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data


def test_query_by_rule() -> None:
    result = _result()
    q = ReasoningQuery((ReasoningQueryFilter(rule_id="dead_section"),))
    out = q.run(result)
    assert len(out) >= 1
    assert all(i.explanation.rule_id == "dead_section" for i in out.inferences)


def test_query_by_kind() -> None:
    result = _result()
    q = ReasoningQuery((ReasoningQueryFilter(kind=InferenceKind.DUPLICATION),))
    out = q.run(result)
    assert all(i.kind is InferenceKind.DUPLICATION for i in out.inferences)


def test_query_deterministic() -> None:
    result = _result()
    q = ReasoningQuery(())
    assert q.run(result).ids() == q.run(result).ids()
