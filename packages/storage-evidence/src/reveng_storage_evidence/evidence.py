"""Canonical evidence model.

Immutable evidence records with deterministic, content-derived identity. Storage
never interprets an evidence ``payload`` — it is opaque, recorded and returned
unchanged. Evidence may reference canonical IR entities by identifier
(``ir_refs``) and an artifact by an opaque string reference (``artifact_ref``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from enum import Enum

from reveng_intermediate_representation import IRIdentifier

from .metadata import EMPTY_METADATA, MetadataBag

__all__ = [
    "EvidenceID",
    "EvidenceKind",
    "EvidenceState",
    "EvidenceOrigin",
    "EvidenceConfidence",
    "Evidence",
    "build_evidence",
]


class EvidenceKind(str, Enum):
    """Representation-level categories of evidence (no analysis semantics)."""

    ARTIFACT = "artifact"
    IR_MODULE = "ir_module"
    IR_NODE = "ir_node"
    PROPERTY = "property"
    RELATION = "relation"
    ANNOTATION = "annotation"
    RAW = "raw"
    UNKNOWN = "unknown"


class EvidenceState(str, Enum):
    """Lifecycle state of an evidence record."""

    DRAFT = "draft"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RETRACTED = "retracted"


class EvidenceConfidence(str, Enum):
    """The frozen five-tier confidence model.

    No total order is implied; promotion between tiers is a later-phase concern.
    """

    OBSERVED = "observed"
    MEASURED = "measured"
    EXTRACTED = "extracted"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EvidenceOrigin:
    """Where a piece of evidence came from — no timestamp, no machine value."""

    origin_kind: str = "unknown"
    reference: str = ""


@dataclass(frozen=True)
class EvidenceID:
    """A content-derived logical identity (hex SHA-256 of a stable key)."""

    value: str

    @classmethod
    def of(cls, key: str) -> EvidenceID:
        if not key:
            raise ValueError("evidence key must be non-empty")
        return cls(hashlib.sha256(key.encode("utf-8")).hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Evidence:
    """An immutable evidence record.

    Identity is stable across versions (derived from a logical key); ``version``
    distinguishes successive records for the same logical id.
    """

    id: EvidenceID
    kind: EvidenceKind
    state: EvidenceState
    origin: EvidenceOrigin
    confidence: EvidenceConfidence
    payload: object | None = None
    ir_refs: tuple[IRIdentifier, ...] = ()
    artifact_ref: str = ""
    metadata: MetadataBag = EMPTY_METADATA
    version: int = 1

    def superseded(self) -> Evidence:
        """Return a copy of this record marked ``SUPERSEDED``."""

        return replace(self, state=EvidenceState.SUPERSEDED)


def build_evidence(
    *,
    key: str,
    kind: EvidenceKind = EvidenceKind.UNKNOWN,
    confidence: EvidenceConfidence = EvidenceConfidence.UNKNOWN,
    state: EvidenceState = EvidenceState.ACTIVE,
    origin: EvidenceOrigin | None = None,
    payload: object | None = None,
    ir_refs: tuple[IRIdentifier, ...] = (),
    artifact_ref: str = "",
    metadata: MetadataBag = EMPTY_METADATA,
    version: int = 1,
) -> Evidence:
    """Construct an :class:`Evidence` record with a deterministic identity."""

    return Evidence(
        id=EvidenceID.of(key),
        kind=kind,
        state=state,
        origin=origin or EvidenceOrigin(),
        confidence=confidence,
        payload=payload,
        ir_refs=ir_refs,
        artifact_ref=artifact_ref,
        metadata=metadata,
        version=version,
    )
