"""Canonical report construction.

``ReportBuilder`` is the only construction path. It consumes an
``InvestigationCase`` (plus its reasoning, evidence, and graph inputs) and a
``Template`` and produces a validated, deterministic ``Report``. It performs no
analysis and never mutates its inputs.
"""

from __future__ import annotations

from collections import Counter

from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .properties import PropertyBag
from .report import Report, ReportID, ReportState
from .templates import ExecutiveSummaryTemplate, RenderContext, Template
from .validation import validate_report

__all__ = ["ReportBuilder"]


class ReportBuilder:
    """Builds a deterministic report from an investigation case."""

    def build(
        self,
        case: InvestigationCase,
        reasoning: ReasoningResult,
        evidence: EvidenceRepository,
        graph: KnowledgeGraph,
        template: Template | None = None,
        *,
        version: int = 1,
    ) -> Report:
        tpl = template or ExecutiveSummaryTemplate()
        context = RenderContext(case=case, reasoning=reasoning, evidence=evidence, graph=graph)
        sections = tpl.render(context)

        report = Report(
            id=ReportID.of(case.id.value, tpl.name, version),
            case_id=case.id.value,
            template=tpl.name,
            title=f"Report: {case.title}",
            summary=self._summary(case),
            sections=sections,
            properties=self._properties(case),
            state=ReportState.DRAFT,
            version=version,
        )
        validate_report(report, case, reasoning, evidence, graph)
        return report

    @staticmethod
    def _properties(case: InvestigationCase) -> PropertyBag:
        severities = ",".join(sorted({f.severity.value for f in case.findings}))
        return PropertyBag.of(
            {"finding_count": len(case.findings), "severities": severities}
        )

    @staticmethod
    def _summary(case: InvestigationCase) -> str:
        kinds = Counter(f.kind.value for f in case.findings)
        parts = ", ".join(f"{k}={kinds[k]}" for k in sorted(kinds))
        return f"{len(case.findings)} findings ({parts})" if parts else "0 findings"
