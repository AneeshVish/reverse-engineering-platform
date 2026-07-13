"""Storage tests: deterministic serialization and round-trip."""

from __future__ import annotations

import dataclasses

import pytest
from _storage_helpers import ir_id, make_evidence
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceDeserializer,
    EvidenceKind,
    EvidenceRepository,
    EvidenceSerializer,
    MetadataBag,
    SerializationError,
    SnapshotBuilder,
    build_evidence,
)


def _snapshot():
    repo = EvidenceRepository()
    repo.add(
        build_evidence(
            key="a",
            kind=EvidenceKind.PROPERTY,
            confidence=EvidenceConfidence.OBSERVED,
            payload={"name": "foo", "n": 3},
            ir_refs=(ir_id("x"),),
            artifact_ref="art1",
            metadata=MetadataBag.of({"tag": "t1"}),
        )
    )
    repo.add(make_evidence("b", payload=[1, 2, 3]))
    return SnapshotBuilder().capture(repo)


def test_serialization_is_deterministic() -> None:
    a = _snapshot()
    b = _snapshot()
    assert EvidenceSerializer().serialize(a) == EvidenceSerializer().serialize(b)


def test_serialization_order_independent() -> None:
    snap = _snapshot()
    reversed_snap = dataclasses.replace(snap, evidence=tuple(reversed(snap.evidence)))
    assert EvidenceSerializer().serialize(snap) == EvidenceSerializer().serialize(reversed_snap)


def test_round_trip_reproduces_equal_snapshot() -> None:
    snap = _snapshot()
    data = EvidenceSerializer().serialize(snap)
    restored = EvidenceDeserializer().deserialize(data)
    assert EvidenceSerializer().serialize(restored) == data


def test_round_trip_preserves_evidence_fields() -> None:
    snap = _snapshot()
    restored = EvidenceDeserializer().deserialize(EvidenceSerializer().serialize(snap))
    original = {e.id.value: e for e in snap.evidence}
    for e in restored.evidence:
        src = original[e.id.value]
        assert e.kind is src.kind
        assert e.confidence is src.confidence
        assert e.payload == src.payload
        assert e.ir_refs == src.ir_refs
        assert e.metadata == src.metadata


def test_non_serializable_payload_raises() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a", payload=object()))
    snap = SnapshotBuilder().capture(repo)
    with pytest.raises(SerializationError):
        EvidenceSerializer().serialize(snap)


def test_invalid_document_raises() -> None:
    with pytest.raises(SerializationError):
        EvidenceDeserializer().deserialize("{not json")


def test_no_timestamp_in_output() -> None:
    data = EvidenceSerializer().serialize(_snapshot())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data
