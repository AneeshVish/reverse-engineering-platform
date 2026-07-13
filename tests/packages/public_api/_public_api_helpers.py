"""Shared test fixtures for the public-api suite.

Uses small, real backend managers (their own reference implementations) --
not hand-rolled mocks -- matching the repo-wide precedent every prior phase's
test suite already follows.
"""

from __future__ import annotations

from fastapi import FastAPI
from reveng_domain_producers import ProducerManager, ProducerRegistry
from reveng_investigation import InvestigationManager
from reveng_knowledge_graph import KnowledgeGraphManager
from reveng_public_api import (
    FixedClock,
    JobManager,
    MonotonicIdProvider,
    PipelineOrchestrator,
    ServiceContext,
    build_service,
    create_app,
)
from reveng_reasoning import ReasoningManager
from reveng_reporting import ReportingManager
from reveng_static_analysis import StaticAnalysisManager
from reveng_storage_evidence import StorageManager

# Recognizable as a PE-ish header so the reference producer classifies it
# deterministically rather than falling back to UNKNOWN/RAW_BINARY on empty input.
TEST_ARTIFACT_BYTES = b"MZ" + b"A" * 512


def build_test_service(
    *, id_provider: MonotonicIdProvider | None = None, clock: FixedClock | None = None
) -> ServiceContext:
    """A fully initialized service with deterministic id/time seams."""

    return build_service(
        id_provider=id_provider or MonotonicIdProvider(), clock=clock or FixedClock()
    )


def make_test_app(service: ServiceContext | None = None) -> tuple[FastAPI, ServiceContext]:
    service = service or build_test_service()
    return create_app(service=service), service


def make_recording_orchestrator(order: list[str]) -> PipelineOrchestrator:
    """A real orchestrator whose 9-manager chain records call order as it runs."""

    class _Producers(ProducerManager):
        def produce(self, request):  # type: ignore[override]
            order.append("produce")
            return super().produce(request)

    class _StaticAnalysis(StaticAnalysisManager):
        def analyze(self, request, *, storage=None):  # type: ignore[override]
            order.append("analyze")
            return super().analyze(request, storage=storage)

    class _KnowledgeGraph(KnowledgeGraphManager):
        def build(self, ir_module, evidence=()):  # type: ignore[override]
            order.append("graph.build")
            return super().build(ir_module, evidence)

    class _Reasoning(ReasoningManager):
        def run(self, graph, evidence):  # type: ignore[override]
            order.append("reasoning.run")
            return super().run(graph, evidence)

    class _Investigation(InvestigationManager):
        def build(self, graph, evidence, reasoning):  # type: ignore[override]
            order.append("investigation.build")
            return super().build(graph, evidence, reasoning)

    class _Reporting(ReportingManager):
        def build(self, case, reasoning, evidence, graph, template_name=None):  # type: ignore[override]
            order.append("reporting.build")
            return super().build(case, reasoning, evidence, graph, template_name=template_name)

        def render(self, report, fmt):  # type: ignore[override]
            order.append("reporting.render")
            return super().render(report, fmt)

    producers = _Producers(ProducerRegistry())
    static_analysis = _StaticAnalysis()
    storage = StorageManager()
    knowledge_graph = _KnowledgeGraph()
    reasoning = _Reasoning()
    investigation = _Investigation()
    reporting = _Reporting()

    for component in (
        producers,
        static_analysis,
        storage,
        knowledge_graph,
        reasoning,
        investigation,
        reporting,
    ):
        component.initialize()

    return PipelineOrchestrator(
        producers=producers,
        static_analysis=static_analysis,
        storage=storage,
        knowledge_graph=knowledge_graph,
        reasoning=reasoning,
        investigation=investigation,
        reporting=reporting,
    )


class _FailingStaticAnalysis(StaticAnalysisManager):
    """A real StaticAnalysisManager whose analyze() always raises, for the
    job-manager failure-path test."""

    def analyze(self, request, *, storage=None):  # type: ignore[override]
        raise RuntimeError("induced failure for testing")


def build_failing_job_manager(
    *, id_provider: MonotonicIdProvider | None = None, clock: FixedClock | None = None
) -> JobManager:
    """A job manager whose pipeline fails at the static-analysis step."""

    producers = ProducerManager(ProducerRegistry())
    producers.initialize()
    static_analysis = _FailingStaticAnalysis()

    orchestrator = PipelineOrchestrator(
        producers=producers,
        static_analysis=static_analysis,
        storage=StorageManager(),
        knowledge_graph=KnowledgeGraphManager(),
        reasoning=ReasoningManager(),
        investigation=InvestigationManager(),
        reporting=ReportingManager(),
    )
    job_manager = JobManager(
        orchestrator, id_provider=id_provider or MonotonicIdProvider(), clock=clock or FixedClock()
    )
    job_manager.initialize()
    return job_manager
