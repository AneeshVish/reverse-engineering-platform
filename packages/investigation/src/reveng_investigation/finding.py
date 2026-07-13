"""The finding model.

A ``Finding`` is an immutable, content-derived organizational unit that groups
existing inferences into an analyst-facing observation. It performs no new
reasoning; every finding records the exact inference, evidence, and graph
elements that produced it. Identity is
``SHA256(kind | subject | sorted inference ids)`` — no timestamps, UUIDs, or
randomness.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = [
    "FindingKind",
    "FindingSeverity",
    "FindingID",
    "FindingExplanation",
    "Finding",
    "build_finding",
]

_SEP = "|"


class FindingKind(str, Enum):
    """The category of an investigation finding."""

    DEAD_CODE = "dead_code"
    UNUSED_FUNCTION = "unused_function"
    DUPLICATE_SYMBOL = "duplicate_symbol"
    MISSING_ENTRY = "missing_entry"
    UNRESOLVED_IMPORT = "unresolved_import"
    DUPLICATE_EVIDENCE = "duplicate_evidence"
    NAMESPACE_INTEGRITY = "namespace_integrity"
    REFERENCE_INTEGRITY = "reference_integrity"


class FindingSeverity(str, Enum):
    """A fixed, deterministic severity label (not a computed score)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class FindingExplanation:
    """The exact provenance of a finding — the whole point of the layer."""

    inference_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    node_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingID:
    """A content-derived finding identity (hex SHA-256)."""

    value: str

    @classmethod
    def of(cls, kind: FindingKind, subject: str, inference_ids: tuple[str, ...]) -> FindingID:
        payload = _SEP.join((kind.value, subject, ",".join(sorted(inference_ids))))
        return cls(hashlib.sha256(payload.encode("utf-8")).hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Finding:
    """An immutable finding grouping existing inferences."""

    id: FindingID
    kind: FindingKind
    severity: FindingSeverity
    subject: str
    title: str
    explanation: FindingExplanation
    properties: PropertyBag = EMPTY_PROPERTIES


def build_finding(
    *,
    kind: FindingKind,
    severity: FindingSeverity,
    subject: str,
    title: str,
    inference_ids: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    node_ids: tuple[str, ...] = (),
    edge_ids: tuple[str, ...] = (),
    properties: PropertyBag = EMPTY_PROPERTIES,
) -> Finding:
    """Construct a ``Finding`` deterministically with a full explanation.

    Identity derives from the kind, subject, and sorted contributing inference
    ids; the explanation records all inference/evidence/graph references so the
    finding is fully traceable.
    """

    explanation = FindingExplanation(
        inference_ids=tuple(sorted(inference_ids)),
        evidence_ids=tuple(sorted(evidence_ids)),
        node_ids=tuple(sorted(node_ids)),
        edge_ids=tuple(sorted(edge_ids)),
    )
    return Finding(
        id=FindingID.of(kind, subject, inference_ids),
        kind=kind,
        severity=severity,
        subject=subject,
        title=title,
        explanation=explanation,
        properties=properties,
    )
