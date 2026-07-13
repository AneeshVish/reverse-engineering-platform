"""Report validation.

Structural only: duplicate section kinds, invalid ids (empty report/case id), and
missing references — every id a section references must resolve to a real finding,
inference, evidence, or graph id from the report's inputs. Report ids are
content-derived, so two reports collide only when built from identical
case/template/version (by design), never accidentally.
"""

from __future__ import annotations

from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .errors import ValidationError
from .report import Report

__all__ = ["validate_report", "ReportValidator"]


def _valid_ids(
    case: InvestigationCase,
    reasoning: ReasoningResult,
    evidence: EvidenceRepository,
    graph: KnowledgeGraph,
) -> set[str]:
    ids: set[str] = set()
    ids.update(f.id.value for f in case.findings)
    ids.update(i.id.value for i in reasoning.inferences)
    ids.update(e.id.value for e in evidence.enumerate())
    ids.update(n.id.value for n in graph.nodes)
    ids.update(e.id.value for e in graph.edges)
    return ids


def validate_report(
    report: Report,
    case: InvestigationCase,
    reasoning: ReasoningResult,
    evidence: EvidenceRepository,
    graph: KnowledgeGraph,
) -> None:
    """Validate a report structurally, raising ``ValidationError`` on failure."""

    if not report.id.value:
        raise ValidationError("report has empty id")
    if not report.case_id:
        raise ValidationError("report has empty case id", report=report.id.value)

    seen_kinds: set[str] = set()
    for section in report.sections:
        if section.kind.value in seen_kinds:
            raise ValidationError("duplicate section", section=section.kind.value)
        seen_kinds.add(section.kind.value)

    valid = _valid_ids(case, reasoning, evidence, graph)
    for section in report.sections:
        for ref in section.references:
            if ref not in valid:
                raise ValidationError(
                    "missing reference", section=section.kind.value, reference=ref
                )


class ReportValidator:
    """Object wrapper around :func:`validate_report`."""

    def validate(
        self,
        report: Report,
        case: InvestigationCase,
        reasoning: ReasoningResult,
        evidence: EvidenceRepository,
        graph: KnowledgeGraph,
    ) -> None:
        validate_report(report, case, reasoning, evidence, graph)
