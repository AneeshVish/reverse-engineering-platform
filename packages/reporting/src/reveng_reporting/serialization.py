"""Canonical, deterministic report serialization.

Serializes a ``Report`` to canonical JSON: sections in order, references sorted,
object keys sorted. The same report always serializes to identical bytes, and a
round-trip reproduces an equal report. No persistence backend.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import SerializationError
from .properties import PropertyBag
from .report import Report, ReportID, ReportState
from .sections import ReportSection, SectionKind

__all__ = ["ReportSerializer", "ReportDeserializer"]


def _enc_section(s: ReportSection) -> dict[str, Any]:
    return {
        "kind": s.kind.value,
        "title": s.title,
        "content": s.content,
        "references": sorted(s.references),
    }


def _dec_section(raw: Any) -> ReportSection:
    return ReportSection(
        kind=SectionKind(raw["kind"]),
        title=raw["title"],
        content=raw["content"],
        references=tuple(raw.get("references", [])),
    )


class ReportSerializer:
    """Serializes a ``Report`` to canonical JSON text."""

    def serialize(self, report: Report) -> str:
        payload = {
            "id": report.id.value,
            "case_id": report.case_id,
            "template": report.template,
            "title": report.title,
            "summary": report.summary,
            "state": report.state.value,
            "version": report.version,
            "sections": [_enc_section(s) for s in report.sections],
            "properties": {k: v for k, v in report.properties.items()},
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class ReportDeserializer:
    """Reconstructs a ``Report`` from canonical JSON text."""

    def deserialize(self, data: str) -> Report:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError("invalid report document", detail=str(exc)) from exc
        return Report(
            id=ReportID(payload["id"]),
            case_id=payload["case_id"],
            template=payload["template"],
            title=payload["title"],
            summary=payload["summary"],
            sections=tuple(_dec_section(s) for s in payload.get("sections", [])),
            properties=PropertyBag.of(dict(payload.get("properties", {}))),
            state=ReportState(payload.get("state", "draft")),
            version=payload.get("version", 1),
        )
