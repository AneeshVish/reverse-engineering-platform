"""The inference model.

An ``Inference`` is an immutable, content-derived fact derived by a rule. Every
inference carries a full ``InferenceExplanation`` — the rule applied and the exact
evidence, graph nodes, and graph edges that produced it — so nothing is hidden.
Identity is ``SHA256(rule_id | subject | fact | sorted-inputs)``; there are no
timestamps, UUIDs, randomness, scores, or probabilities.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = [
    "InferenceKind",
    "InferenceState",
    "InferenceExplanation",
    "InferenceID",
    "Inference",
    "build_inference",
]

_SEP = "|"


class InferenceKind(str, Enum):
    """Semantic category of a derived fact."""

    STRUCTURAL = "structural"
    REFERENCE = "reference"
    DUPLICATION = "duplication"
    COMPLETENESS = "completeness"
    PROVENANCE = "provenance"


class InferenceState(str, Enum):
    """Lifecycle state of an inference."""

    DERIVED = "derived"
    RETRACTED = "retracted"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class InferenceExplanation:
    """The exact chain that produced an inference — the whole point of the engine."""

    rule_id: str
    output_fact: str
    input_evidence: tuple[str, ...] = ()
    input_nodes: tuple[str, ...] = ()
    input_edges: tuple[str, ...] = ()

    def canonical(self) -> str:
        """A stable string of all inputs, used for identity derivation."""

        parts = (
            ",".join(sorted(self.input_evidence)),
            ",".join(sorted(self.input_nodes)),
            ",".join(sorted(self.input_edges)),
        )
        return _SEP.join(parts)


@dataclass(frozen=True)
class InferenceID:
    """A content-derived inference identity (hex SHA-256)."""

    value: str

    @classmethod
    def of(cls, rule_id: str, subject: str, fact: str, inputs_canonical: str) -> InferenceID:
        digest = hashlib.sha256(
            _SEP.join((rule_id, subject, fact, inputs_canonical)).encode("utf-8")
        )
        return cls(digest.hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Inference:
    """An immutable derived fact with a full explanation chain."""

    id: InferenceID
    kind: InferenceKind
    state: InferenceState
    subject: str
    fact: str
    explanation: InferenceExplanation
    properties: PropertyBag = field(default_factory=lambda: EMPTY_PROPERTIES)


def build_inference(
    *,
    rule_id: str,
    kind: InferenceKind,
    subject: str,
    fact: str,
    input_evidence: tuple[str, ...] = (),
    input_nodes: tuple[str, ...] = (),
    input_edges: tuple[str, ...] = (),
    properties: PropertyBag = EMPTY_PROPERTIES,
) -> Inference:
    """Construct an ``Inference`` deterministically with a full explanation.

    This is the only construction path rules use, so identity derivation is never
    duplicated: the id is derived from the rule, subject, fact, and the sorted
    inputs.
    """

    explanation = InferenceExplanation(
        rule_id=rule_id,
        output_fact=fact,
        input_evidence=input_evidence,
        input_nodes=input_nodes,
        input_edges=input_edges,
    )
    return Inference(
        id=InferenceID.of(rule_id, subject, fact, explanation.canonical()),
        kind=kind,
        state=InferenceState.DERIVED,
        subject=subject,
        fact=fact,
        explanation=explanation,
        properties=properties,
    )
