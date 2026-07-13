"""Report templates — pure deterministic section formatting.

A ``Template`` transforms a read-only ``RenderContext`` (the investigation case
plus its reasoning, evidence, and graph inputs) into a tuple of report sections.
Templates perform no analysis — they format already-derived information, and every
section references upstream ids only. All output is deterministic (sorted, no
timestamps or randomness).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass

from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .sections import ReportSection, SectionKind

__all__ = [
    "RenderContext",
    "Template",
    "ExecutiveSummaryTemplate",
    "TechnicalTemplate",
    "EvidenceTemplate",
    "JSONTemplate",
    "MarkdownTemplate",
    "REFERENCE_TEMPLATE_TYPES",
]


@dataclass(frozen=True)
class RenderContext:
    """Read-only inputs handed to a template."""

    case: InvestigationCase
    reasoning: ReasoningResult
    evidence: EvidenceRepository
    graph: KnowledgeGraph

    def inference_facts(self) -> dict[str, str]:
        return {i.id.value: i.fact for i in self.reasoning.inferences}


def _collect(case: InvestigationCase, attr: str) -> tuple[str, ...]:
    ids: set[str] = set()
    for finding in case.findings:
        ids.update(getattr(finding.explanation, attr))
    return tuple(sorted(ids))


def _summary_section(ctx: RenderContext) -> ReportSection:
    case = ctx.case
    kinds = Counter(f.kind.value for f in case.findings)
    severities = Counter(f.severity.value for f in case.findings)
    lines = [
        f"findings: {len(case.findings)}",
        f"priority: {case.priority.value}",
        "kinds: " + ", ".join(f"{k}={kinds[k]}" for k in sorted(kinds)),
        "severities: " + ", ".join(f"{s}={severities[s]}" for s in sorted(severities)),
    ]
    return ReportSection(SectionKind.SUMMARY, "Summary", "\n".join(lines))


def _findings_section(ctx: RenderContext) -> ReportSection:
    findings = sorted(ctx.case.findings, key=lambda f: f.id.value)
    lines = [f"[{f.severity.value}] {f.kind.value}: {f.title}" for f in findings]
    refs = tuple(f.id.value for f in findings)
    return ReportSection(SectionKind.FINDINGS, "Findings", "\n".join(lines), refs)


def _inferences_section(ctx: RenderContext) -> ReportSection:
    facts = ctx.inference_facts()
    refs = _collect(ctx.case, "inference_ids")
    lines = [f"{iid[:12]}: {facts.get(iid, '(unknown)')}" for iid in refs]
    return ReportSection(SectionKind.INFERENCES, "Inferences", "\n".join(lines), refs)


def _evidence_section(ctx: RenderContext) -> ReportSection:
    refs = _collect(ctx.case, "evidence_ids")
    lines = [f"evidence {eid[:12]}" for eid in refs]
    return ReportSection(SectionKind.EVIDENCE, "Evidence", "\n".join(lines), refs)


def _graph_section(ctx: RenderContext) -> ReportSection:
    nodes = _collect(ctx.case, "node_ids")
    edges = _collect(ctx.case, "edge_ids")
    content = f"nodes: {len(nodes)}\nedges: {len(edges)}"
    return ReportSection(SectionKind.GRAPH, "Graph", content, tuple(sorted(nodes + edges)))


class Template(ABC):
    """A pure, deterministic report template."""

    name_: str = ""

    @property
    def name(self) -> str:
        return self.name_

    @abstractmethod
    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        """Produce report sections from the context."""


class ExecutiveSummaryTemplate(Template):
    name_ = "executive_summary"

    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        return (_summary_section(context), _findings_section(context))


class TechnicalTemplate(Template):
    name_ = "technical"

    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        return (
            _summary_section(context),
            _findings_section(context),
            _inferences_section(context),
            _evidence_section(context),
            _graph_section(context),
        )


class EvidenceTemplate(Template):
    name_ = "evidence"

    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        return (_findings_section(context), _evidence_section(context))


class JSONTemplate(Template):
    name_ = "json"

    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        return (_summary_section(context), _findings_section(context))


class MarkdownTemplate(Template):
    name_ = "markdown"

    def render(self, context: RenderContext) -> tuple[ReportSection, ...]:
        findings = sorted(context.case.findings, key=lambda f: f.id.value)
        md_lines = [f"- **{f.severity.value}** `{f.kind.value}` — {f.title}" for f in findings]
        findings_section = ReportSection(
            SectionKind.FINDINGS,
            "Findings",
            "\n".join(md_lines),
            tuple(f.id.value for f in findings),
        )
        return (_summary_section(context), findings_section)


REFERENCE_TEMPLATE_TYPES: tuple[type[Template], ...] = (
    ExecutiveSummaryTemplate,
    TechnicalTemplate,
    EvidenceTemplate,
    JSONTemplate,
    MarkdownTemplate,
)
