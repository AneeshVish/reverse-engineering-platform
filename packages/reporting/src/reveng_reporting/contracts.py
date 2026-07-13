"""Protocol definitions later packages implement.

These describe how future packages provide, consume, and build reports. They are
protocols only; the concrete builder is ``ReportBuilder`` in ``builders.py`` (the
builder protocol here is named ``ReportBuilderProtocol`` to avoid the name clash).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .report import Report

__all__ = ["ReportProvider", "ReportConsumer", "ReportBuilderProtocol"]


@runtime_checkable
class ReportProvider(Protocol):
    """Produces a ``Report`` (implemented by later packages)."""

    def provide(self) -> Report: ...


@runtime_checkable
class ReportConsumer(Protocol):
    """Consumes a ``Report`` (implemented by later packages)."""

    def consume(self, report: Report) -> None: ...


@runtime_checkable
class ReportBuilderProtocol(Protocol):
    """Builds a ``Report`` from an investigation case and its inputs."""

    def build(
        self,
        case: InvestigationCase,
        reasoning: ReasoningResult,
        evidence: EvidenceRepository,
        graph: KnowledgeGraph,
    ) -> Report: ...
