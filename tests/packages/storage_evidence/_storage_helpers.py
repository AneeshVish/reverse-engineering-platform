"""Shared builders for storage-evidence tests."""

from __future__ import annotations

from reveng_intermediate_representation import IRIdentifier
from reveng_storage_evidence import (
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    build_evidence,
)


def ir_id(seed: str) -> IRIdentifier:
    return IRIdentifier((seed * 64)[:64])


def make_evidence(
    key: str,
    *,
    kind: EvidenceKind = EvidenceKind.PROPERTY,
    confidence: EvidenceConfidence = EvidenceConfidence.OBSERVED,
    payload: object | None = None,
    ir_refs: tuple[IRIdentifier, ...] = (),
    artifact_ref: str = "",
) -> Evidence:
    return build_evidence(
        key=key,
        kind=kind,
        confidence=confidence,
        payload=payload,
        ir_refs=ir_refs,
        artifact_ref=artifact_ref,
    )
