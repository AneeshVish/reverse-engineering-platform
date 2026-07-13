"""Canonical investigation construction.

``InvestigationBuilder`` is the only construction path. It consumes a
``KnowledgeGraph``, an ``EvidenceRepository``, and a ``ReasoningResult``, runs the
reference investigations to group existing inferences into findings, and produces
a validated, deterministic ``InvestigationCase``. It performs no new reasoning and
never mutates its inputs.
"""

from __future__ import annotations

from dataclasses import dataclass

from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .case import CaseID, CasePriority, CaseStatus, InvestigationCase
from .finding import Finding, FindingSeverity
from .reference import run_reference_investigations
from .timeline import Timeline, build_timeline
from .validation import validate_case

__all__ = ["InvestigationView", "InvestigationBuilder"]

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

_SEVERITY_TO_PRIORITY: dict[FindingSeverity, CasePriority] = {
    FindingSeverity.INFO: CasePriority.LOW,
    FindingSeverity.LOW: CasePriority.LOW,
    FindingSeverity.MEDIUM: CasePriority.MEDIUM,
    FindingSeverity.HIGH: CasePriority.HIGH,
    FindingSeverity.CRITICAL: CasePriority.CRITICAL,
}


@dataclass(frozen=True)
class InvestigationView:
    """An immutable analyst view: a case together with its timeline."""

    case: InvestigationCase
    timeline: Timeline


class InvestigationBuilder:
    """Builds a deterministic investigation case from analysis outputs."""

    def build(
        self,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> InvestigationCase:
        findings = tuple(
            sorted(run_reference_investigations(reasoning), key=lambda f: f.id.value)
        )
        inference_ids: set[str] = set()
        for finding in findings:
            inference_ids.update(finding.explanation.inference_ids)

        case = InvestigationCase(
            id=CaseID.of(tuple(inference_ids)),
            status=CaseStatus.OPEN,
            priority=self._priority(findings),
            title=f"investigation ({len(findings)} findings)",
            findings=findings,
        )
        validate_case(case, graph, evidence, reasoning)
        return case

    def build_view(
        self,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> InvestigationView:
        case = self.build(graph, evidence, reasoning)
        return InvestigationView(case=case, timeline=build_timeline(case))

    @staticmethod
    def _priority(findings: tuple[Finding, ...]) -> CasePriority:
        if not findings:
            return CasePriority.LOW
        top = max(findings, key=lambda f: _SEVERITY_ORDER[f.severity]).severity
        return _SEVERITY_TO_PRIORITY[top]
