"""Reasoning-result validation.

Structural only: duplicate inference ids, invalid outputs (empty fact or rule id),
missing evidence (an explanation cites an evidence id absent from the repository),
and dangling graph references (an explanation cites a node/edge id absent from the
graph). Inferences reference the graph and evidence but never other inferences, so
they are acyclic by construction; this is asserted here.
"""

from __future__ import annotations

from reveng_knowledge_graph import KnowledgeGraph
from reveng_storage_evidence import EvidenceID, EvidenceRepository

from .engine import ReasoningResult
from .errors import ValidationError

__all__ = ["validate_result", "ResultValidator"]


def validate_result(
    result: ReasoningResult,
    graph: KnowledgeGraph,
    evidence: EvidenceRepository,
) -> None:
    """Validate a reasoning result, raising ``ValidationError`` on failure."""

    node_ids = {n.id.value for n in graph.nodes}
    edge_ids = {e.id.value for e in graph.edges}

    seen: set[str] = set()
    for inf in result.inferences:
        if not inf.id.value:
            raise ValidationError("inference has empty id", fact=inf.fact)
        if inf.id.value in seen:
            raise ValidationError("duplicate inference id", inference=inf.id.value)
        seen.add(inf.id.value)

        if not inf.fact or not inf.explanation.rule_id:
            raise ValidationError("invalid inference output", inference=inf.id.value)

        for ev in inf.explanation.input_evidence:
            if not evidence.contains(EvidenceID(ev)):
                raise ValidationError(
                    "missing evidence reference", inference=inf.id.value, evidence=ev
                )
        for node in inf.explanation.input_nodes:
            if node not in node_ids:
                raise ValidationError(
                    "dangling node reference", inference=inf.id.value, node=node
                )
        for edge in inf.explanation.input_edges:
            if edge not in edge_ids:
                raise ValidationError(
                    "dangling edge reference", inference=inf.id.value, edge=edge
                )


class ResultValidator:
    """Object wrapper around :func:`validate_result`."""

    def validate(
        self,
        result: ReasoningResult,
        graph: KnowledgeGraph,
        evidence: EvidenceRepository,
    ) -> None:
        validate_result(result, graph, evidence)
