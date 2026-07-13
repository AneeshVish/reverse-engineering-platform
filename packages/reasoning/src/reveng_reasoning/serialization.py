"""Canonical, deterministic reasoning-result serialization.

Serializes a ``ReasoningResult`` to canonical JSON: inferences sorted by id,
object keys sorted, explanation inputs sorted. The same result always serializes
to identical bytes, and a round-trip reproduces an equal result. No persistence
backend.
"""

from __future__ import annotations

import json
from typing import Any

from .engine import ReasoningResult
from .errors import SerializationError
from .inference import (
    Inference,
    InferenceExplanation,
    InferenceID,
    InferenceKind,
    InferenceState,
)
from .properties import PropertyBag

__all__ = ["ReasoningSerializer", "ReasoningDeserializer"]


def _enc(inf: Inference) -> dict[str, Any]:
    return {
        "id": inf.id.value,
        "kind": inf.kind.value,
        "state": inf.state.value,
        "subject": inf.subject,
        "fact": inf.fact,
        "explanation": {
            "rule_id": inf.explanation.rule_id,
            "output_fact": inf.explanation.output_fact,
            "input_evidence": sorted(inf.explanation.input_evidence),
            "input_nodes": sorted(inf.explanation.input_nodes),
            "input_edges": sorted(inf.explanation.input_edges),
        },
        "properties": {k: v for k, v in inf.properties.items()},
    }


def _dec(raw: Any) -> Inference:
    exp = raw["explanation"]
    return Inference(
        id=InferenceID(raw["id"]),
        kind=InferenceKind(raw["kind"]),
        state=InferenceState(raw["state"]),
        subject=raw["subject"],
        fact=raw["fact"],
        explanation=InferenceExplanation(
            rule_id=exp["rule_id"],
            output_fact=exp["output_fact"],
            input_evidence=tuple(exp.get("input_evidence", [])),
            input_nodes=tuple(exp.get("input_nodes", [])),
            input_edges=tuple(exp.get("input_edges", [])),
        ),
        properties=PropertyBag.of(dict(raw.get("properties", {}))),
    )


class ReasoningSerializer:
    """Serializes a ``ReasoningResult`` to canonical JSON text."""

    def serialize(self, result: ReasoningResult) -> str:
        rows = sorted((_enc(i) for i in result.inferences), key=lambda d: d["id"])
        return json.dumps({"inferences": rows}, sort_keys=True, separators=(",", ":"))


class ReasoningDeserializer:
    """Reconstructs a ``ReasoningResult`` from canonical JSON text."""

    def deserialize(self, data: str) -> ReasoningResult:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid reasoning document", detail=str(exc)) from exc
        return ReasoningResult(tuple(_dec(r) for r in payload.get("inferences", [])))
