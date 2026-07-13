"""Storage tests: evidence model — identity, tiers, immutability."""

from __future__ import annotations

import dataclasses

import pytest
from _storage_helpers import make_evidence
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceID,
    EvidenceState,
    MetadataBag,
)


def test_evidence_id_is_deterministic() -> None:
    assert EvidenceID.of("k") == EvidenceID.of("k")
    assert EvidenceID.of("k").value != EvidenceID.of("j").value


def test_evidence_id_is_sha256_hex() -> None:
    v = EvidenceID.of("k").value
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_empty_key_rejected() -> None:
    with pytest.raises(ValueError):
        EvidenceID.of("")


def test_confidence_tiers_present() -> None:
    tiers = {c.value for c in EvidenceConfidence}
    assert tiers == {"observed", "measured", "extracted", "inferred", "unknown"}


def test_evidence_is_immutable() -> None:
    ev = make_evidence("a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.version = 5  # type: ignore[misc]


def test_superseded_returns_new_record() -> None:
    ev = make_evidence("a")
    sup = ev.superseded()
    assert sup.state is EvidenceState.SUPERSEDED
    assert ev.state is EvidenceState.ACTIVE  # original unchanged
    assert sup is not ev


def test_metadata_key_sorted() -> None:
    bag = MetadataBag.of({"z": 1, "a": 2})
    assert bag.keys() == ("a", "z")
