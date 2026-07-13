"""Investigation-case validation.

Structural only: duplicate finding ids, invalid explanations (empty title), and
dangling references — every inference id must exist in the reasoning result, every
evidence id in the repository, and every node/edge id in the graph. Findings never
reference other findings, so cases are acyclic by construction.
"""

from __future__ import annotations

from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceID, EvidenceRepository

from .case import InvestigationCase
from .errors import ValidationError

__all__ = ["validate_case", "CaseValidator"]


def validate_case(
    case: InvestigationCase,
    graph: KnowledgeGraph,
    evidence: EvidenceRepository,
    reasoning: ReasoningResult,
) -> None:
    """Validate a case structurally, raising ``ValidationError`` on failure."""

    node_ids = {n.id.value for n in graph.nodes}
    edge_ids = {e.id.value for e in graph.edges}
    inference_ids = {i.id.value for i in reasoning.inferences}

    seen: set[str] = set()
    for finding in case.findings:
        if not finding.id.value:
            raise ValidationError("finding has empty id", title=finding.title)
        if finding.id.value in seen:
            raise ValidationError("duplicate finding", finding=finding.id.value)
        seen.add(finding.id.value)

        if not finding.title:
            raise ValidationError("invalid finding explanation", finding=finding.id.value)

        exp = finding.explanation
        for inf in exp.inference_ids:
            if inf not in inference_ids:
                raise ValidationError(
                    "dangling inference reference", finding=finding.id.value, inference=inf
                )
        for ev in exp.evidence_ids:
            if not evidence.contains(EvidenceID(ev)):
                raise ValidationError(
                    "dangling evidence reference", finding=finding.id.value, evidence=ev
                )
        for node in exp.node_ids:
            if node not in node_ids:
                raise ValidationError(
                    "dangling node reference", finding=finding.id.value, node=node
                )
        for edge in exp.edge_ids:
            if edge not in edge_ids:
                raise ValidationError(
                    "dangling edge reference", finding=finding.id.value, edge=edge
                )


class CaseValidator:
    """Object wrapper around :func:`validate_case`."""

    def validate(
        self,
        case: InvestigationCase,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
        reasoning: ReasoningResult,
    ) -> None:
        validate_case(case, graph, evidence, reasoning)
