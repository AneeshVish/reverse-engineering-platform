"""Base scaffolding for reference investigations.

A ``ReferenceInvestigation`` selects inferences produced by specific reasoning
rules and groups each into a ``Finding``. It performs no new reasoning — it merely
organizes existing inference objects. Concrete investigations set a few class
attributes; ``build`` does the deterministic mapping.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from reveng_reasoning import ReasoningResult

from ..finding import Finding, FindingKind, FindingSeverity, build_finding

__all__ = ["ReferenceInvestigation"]


class ReferenceInvestigation(ABC):
    """Groups inferences from a set of reasoning rules into findings."""

    kind_: FindingKind
    severity_: FindingSeverity
    rule_ids_: frozenset[str] = frozenset()

    @property
    def kind(self) -> FindingKind:
        return self.kind_

    def build(self, reasoning: ReasoningResult) -> tuple[Finding, ...]:
        findings = []
        for inference in reasoning.inferences:
            if inference.explanation.rule_id not in self.rule_ids_:
                continue
            findings.append(
                build_finding(
                    kind=self.kind_,
                    severity=self.severity_,
                    subject=inference.subject,
                    title=inference.fact,
                    inference_ids=(inference.id.value,),
                    evidence_ids=inference.explanation.input_evidence,
                    node_ids=inference.explanation.input_nodes,
                    edge_ids=inference.explanation.input_edges,
                )
            )
        return tuple(findings)

    @abstractmethod
    def name(self) -> str:
        """A stable human-readable investigation name."""
