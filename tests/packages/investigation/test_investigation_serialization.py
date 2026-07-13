"""Investigation tests: serialization, round-trip, indexes, and queries."""

from __future__ import annotations

import dataclasses

import pytest
from _investigation_helpers import build_pipeline
from reveng_investigation import (
    EvidenceIndex,
    FindingIndex,
    FindingKind,
    InferenceIndex,
    InvestigationBuilder,
    InvestigationDeserializer,
    InvestigationQuery,
    InvestigationQueryFilter,
    InvestigationSerializer,
    SerializationError,
)


def _case():
    graph, repo, reasoning = build_pipeline()
    return InvestigationBuilder().build(graph, repo, reasoning)


def test_serialization_is_deterministic() -> None:
    ser = InvestigationSerializer()
    assert ser.serialize(_case()) == ser.serialize(_case())


def test_serialization_order_independent() -> None:
    case = _case()
    rev = dataclasses.replace(case, findings=tuple(reversed(case.findings)))
    assert InvestigationSerializer().serialize(case) == InvestigationSerializer().serialize(rev)


def test_round_trip_reproduces_equal_case() -> None:
    case = _case()
    data = InvestigationSerializer().serialize(case)
    restored = InvestigationDeserializer().deserialize(data)
    assert InvestigationSerializer().serialize(restored) == data


def test_round_trip_preserves_findings() -> None:
    case = _case()
    restored = InvestigationDeserializer().deserialize(InvestigationSerializer().serialize(case))
    assert {f.id.value for f in restored.findings} == {f.id.value for f in case.findings}


def test_invalid_document_raises() -> None:
    with pytest.raises(SerializationError):
        InvestigationDeserializer().deserialize("{not json")


def test_no_timestamp_in_output() -> None:
    data = InvestigationSerializer().serialize(_case())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data


def test_finding_index() -> None:
    case = _case()
    idx = FindingIndex.build(case)
    for f in case.findings:
        assert idx.get(f.id.value) is not None


def test_inference_and_evidence_indexes() -> None:
    case = _case()
    inf_idx = InferenceIndex.build(case)
    ev_idx = EvidenceIndex.build(case)
    # Every finding's inference is indexed back to that finding.
    for f in case.findings:
        for inf in f.explanation.inference_ids:
            assert f.id.value in inf_idx.lookup(inf)
        for ev in f.explanation.evidence_ids:
            assert f.id.value in ev_idx.lookup(ev)


def test_query_by_kind() -> None:
    case = _case()
    out = InvestigationQuery((InvestigationQueryFilter(kind=FindingKind.DEAD_CODE),)).run(case)
    assert all(f.kind is FindingKind.DEAD_CODE for f in out.findings)
    assert len(out) >= 1


def test_query_deterministic() -> None:
    case = _case()
    q = InvestigationQuery(())
    assert q.run(case).ids() == q.run(case).ids()
