"""Domain-producer tests: the immutable artifact contract."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

import pytest
from reveng_domain_producers import (
    Artifact,
    ArtifactState,
    ArtifactType,
    build_artifact,
)


def _artifact(
    content: bytes = b"data",
    *,
    metadata: Mapping[str, Any] | None = None,
    capabilities: tuple[str, ...] = (),
    state: ArtifactState = ArtifactState.PRODUCED,
) -> Artifact:
    return build_artifact(
        content=content,
        source_ref="ref",
        artifact_type=ArtifactType.RAW_BINARY,
        producer_name="p",
        producer_version="1.0.0",
        metadata=metadata,
        capabilities=capabilities,
        state=state,
    )


def test_identity_is_content_sha256() -> None:
    art = _artifact(content=b"hello")
    assert art.identity.content_hash == hashlib.sha256(b"hello").hexdigest()


def test_same_content_same_identity() -> None:
    assert _artifact(content=b"x").identity == _artifact(content=b"x").identity


def test_source_records_size() -> None:
    art = _artifact(content=b"12345")
    assert art.source.size == 5
    assert art.source.ref == "ref"


def test_provenance_has_no_timestamp_fields() -> None:
    prov = _artifact().provenance
    assert prov.producer_name == "p"
    assert prov.producer_version == "1.0.0"
    assert prov.source_ref == "ref"
    # No time/uuid/machine attributes exist on the provenance contract.
    for banned in ("timestamp", "created_at", "uuid", "host", "machine"):
        assert not hasattr(prov, banned)


def test_metadata_is_read_only() -> None:
    art = _artifact(metadata={"k": 1})
    assert art.metadata["k"] == 1
    with pytest.raises(TypeError):
        art.metadata["k"] = 2  # type: ignore[index]


def test_capabilities_preserved_in_order() -> None:
    art = _artifact(capabilities=("b", "a"))
    assert art.capabilities == ("b", "a")


def test_default_state_is_produced() -> None:
    assert _artifact().state is ArtifactState.PRODUCED


def test_equality_and_hash_by_content() -> None:
    a = _artifact(content=b"x", metadata={"k": 1})
    b = _artifact(content=b"x", metadata={"k": 1})
    assert a == b
    assert hash(a) == hash(b)
    assert a != _artifact(content=b"y", metadata={"k": 1})


def test_artifact_has_no_public_setters() -> None:
    art = _artifact()
    with pytest.raises(AttributeError):
        art.producer = "other"  # type: ignore[misc]
