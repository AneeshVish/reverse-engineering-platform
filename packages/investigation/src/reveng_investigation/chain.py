"""Immutable evidence, graph, and inference chains.

Chains are pure, immutable reference bundles that link a finding back to the
inference, evidence, and graph elements it was built from. They hold identifiers
only — never copies of the referenced objects — so nothing upstream is mutated.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import Finding

__all__ = ["InferenceChain", "EvidenceChain", "GraphChain", "chains_for"]


@dataclass(frozen=True)
class InferenceChain:
    """The inference ids that contributed to a finding, in sorted order."""

    inference_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceChain:
    """The evidence ids referenced by a finding, in sorted order."""

    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class GraphChain:
    """The graph node and edge ids referenced by a finding, in sorted order."""

    node_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()


def chains_for(finding: Finding) -> tuple[InferenceChain, EvidenceChain, GraphChain]:
    """Derive the three immutable chains for a finding from its explanation."""

    exp = finding.explanation
    return (
        InferenceChain(exp.inference_ids),
        EvidenceChain(exp.evidence_ids),
        GraphChain(exp.node_ids, exp.edge_ids),
    )
