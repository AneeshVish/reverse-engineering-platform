"""The rule abstraction.

A ``Rule`` is a pure, deterministic function over a read-only ``RuleContext`` (the
knowledge graph and the evidence repository) that returns a ``RuleResult`` of
``Inference`` objects. Rules never mutate their inputs and never introduce
timestamps, randomness, scores, or heuristics — they match explicit patterns only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from reveng_knowledge_graph import GraphNodeKind, KnowledgeGraph, RelationshipKind
from reveng_storage_evidence import EvidenceRepository

from .inference import Inference, InferenceKind

__all__ = [
    "RuleID",
    "RuleRequirement",
    "RuleMetadata",
    "RuleContext",
    "RuleResult",
    "Rule",
    "DEFAULT_PRIORITY",
]

RuleID = str
DEFAULT_PRIORITY = 100


@dataclass(frozen=True)
class RuleRequirement:
    """What a rule needs present in the graph to be applicable.

    Empty requirements mean the rule always applies. A rule that is applicable but
    finds no match simply returns zero inferences.
    """

    node_kinds: tuple[GraphNodeKind, ...] = ()
    relationships: tuple[RelationshipKind, ...] = ()


@dataclass(frozen=True)
class RuleMetadata:
    """A rule's self-description."""

    identifier: str
    version: str = "1.0.0"
    inference_kind: InferenceKind = InferenceKind.STRUCTURAL
    priority: int = DEFAULT_PRIORITY
    description: str = ""
    requirement: RuleRequirement = field(default_factory=RuleRequirement)


@dataclass(frozen=True)
class RuleContext:
    """Read-only inputs handed to a rule."""

    graph: KnowledgeGraph
    evidence: EvidenceRepository


@dataclass(frozen=True)
class RuleResult:
    """The inferences a rule produced."""

    rule_id: str
    inferences: tuple[Inference, ...] = ()


class Rule(ABC):
    """Abstract deterministic inference rule."""

    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """Return this rule's self-description."""

    @property
    def identifier(self) -> str:
        return self.metadata.identifier

    def applies_to(self, graph: KnowledgeGraph) -> bool:
        """Whether this rule's required node kinds are present in ``graph``."""

        requirement = self.metadata.requirement
        if not requirement.node_kinds:
            return True
        present = {n.kind for n in graph.nodes}
        return all(kind in present for kind in requirement.node_kinds)

    @abstractmethod
    def apply(self, context: RuleContext) -> RuleResult:
        """Match the rule's pattern and return derived inferences."""
