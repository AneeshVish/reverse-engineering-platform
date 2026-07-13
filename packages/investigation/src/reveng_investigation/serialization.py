"""Canonical, deterministic investigation-case serialization.

Serializes an ``InvestigationCase`` to canonical JSON: findings sorted by id,
explanation id lists sorted, object keys sorted. The same case always serializes
to identical bytes, and a round-trip reproduces an equal case. No persistence
backend.
"""

from __future__ import annotations

import json
from typing import Any

from .case import CaseID, CasePriority, CaseStatus, InvestigationCase
from .errors import SerializationError
from .finding import (
    Finding,
    FindingExplanation,
    FindingID,
    FindingKind,
    FindingSeverity,
)
from .properties import PropertyBag

__all__ = ["InvestigationSerializer", "InvestigationDeserializer"]


def _enc_finding(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id.value,
        "kind": f.kind.value,
        "severity": f.severity.value,
        "subject": f.subject,
        "title": f.title,
        "explanation": {
            "inference_ids": sorted(f.explanation.inference_ids),
            "evidence_ids": sorted(f.explanation.evidence_ids),
            "node_ids": sorted(f.explanation.node_ids),
            "edge_ids": sorted(f.explanation.edge_ids),
        },
        "properties": {k: v for k, v in f.properties.items()},
    }


def _dec_finding(raw: Any) -> Finding:
    exp = raw["explanation"]
    return Finding(
        id=FindingID(raw["id"]),
        kind=FindingKind(raw["kind"]),
        severity=FindingSeverity(raw["severity"]),
        subject=raw["subject"],
        title=raw["title"],
        explanation=FindingExplanation(
            inference_ids=tuple(exp.get("inference_ids", [])),
            evidence_ids=tuple(exp.get("evidence_ids", [])),
            node_ids=tuple(exp.get("node_ids", [])),
            edge_ids=tuple(exp.get("edge_ids", [])),
        ),
        properties=PropertyBag.of(dict(raw.get("properties", {}))),
    )


class InvestigationSerializer:
    """Serializes an ``InvestigationCase`` to canonical JSON text."""

    def serialize(self, case: InvestigationCase) -> str:
        findings = sorted((_enc_finding(f) for f in case.findings), key=lambda d: d["id"])
        payload = {
            "id": case.id.value,
            "status": case.status.value,
            "priority": case.priority.value,
            "title": case.title,
            "findings": findings,
            "properties": {k: v for k, v in case.properties.items()},
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class InvestigationDeserializer:
    """Reconstructs an ``InvestigationCase`` from canonical JSON text."""

    def deserialize(self, data: str) -> InvestigationCase:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid investigation document", detail=str(exc)) from exc
        return InvestigationCase(
            id=CaseID(payload["id"]),
            status=CaseStatus(payload["status"]),
            priority=CasePriority(payload["priority"]),
            title=payload["title"],
            findings=tuple(_dec_finding(f) for f in payload.get("findings", [])),
            properties=PropertyBag.of(dict(payload.get("properties", {}))),
        )
