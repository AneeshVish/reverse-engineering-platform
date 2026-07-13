"""Canonical, deterministic serialization of repository snapshots.

Serializes a ``RepositorySnapshot`` to canonical JSON: evidence sorted by id,
object keys sorted. The same snapshot always serializes to identical bytes, and a
round-trip reproduces an equal snapshot. Payloads must be JSON-encodable;
anything else raises ``SerializationError`` (payloads are opaque but must be
representable to round-trip). No persistence backend is involved.
"""

from __future__ import annotations

import json
from typing import Any

from reveng_intermediate_representation import IRIdentifier

from .errors import SerializationError
from .evidence import (
    Evidence,
    EvidenceConfidence,
    EvidenceID,
    EvidenceKind,
    EvidenceOrigin,
    EvidenceState,
)
from .metadata import MetadataBag
from .snapshot import RepositorySnapshot

__all__ = ["EvidenceSerializer", "EvidenceDeserializer"]


def _enc_evidence(e: Evidence) -> dict[str, Any]:
    return {
        "id": e.id.value,
        "kind": e.kind.value,
        "state": e.state.value,
        "origin": {"origin_kind": e.origin.origin_kind, "reference": e.origin.reference},
        "confidence": e.confidence.value,
        "payload": e.payload,
        "ir_refs": [r.value for r in e.ir_refs],
        "artifact_ref": e.artifact_ref,
        "metadata": {k: v for k, v in e.metadata.items()},
        "version": e.version,
    }


def _dec_evidence(raw: Any) -> Evidence:
    origin = raw.get("origin", {})
    return Evidence(
        id=EvidenceID(raw["id"]),
        kind=EvidenceKind(raw["kind"]),
        state=EvidenceState(raw["state"]),
        origin=EvidenceOrigin(
            origin_kind=origin.get("origin_kind", "unknown"),
            reference=origin.get("reference", ""),
        ),
        confidence=EvidenceConfidence(raw["confidence"]),
        payload=raw.get("payload"),
        ir_refs=tuple(IRIdentifier(v) for v in raw.get("ir_refs", [])),
        artifact_ref=raw.get("artifact_ref", ""),
        metadata=MetadataBag.of(dict(raw.get("metadata", {}))),
        version=raw.get("version", 1),
    )


class EvidenceSerializer:
    """Serializes a ``RepositorySnapshot`` to canonical JSON text."""

    def serialize(self, snapshot: RepositorySnapshot) -> str:
        records = sorted((_enc_evidence(e) for e in snapshot.evidence), key=lambda d: d["id"])
        try:
            return json.dumps({"evidence": records}, sort_keys=True, separators=(",", ":"))
        except TypeError as exc:
            raise SerializationError("evidence payload is not serializable", detail=str(exc)) from exc


class EvidenceDeserializer:
    """Reconstructs a ``RepositorySnapshot`` from canonical JSON text."""

    def deserialize(self, data: str) -> RepositorySnapshot:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid evidence document", detail=str(exc)) from exc
        return RepositorySnapshot(tuple(_dec_evidence(r) for r in payload.get("evidence", [])))
