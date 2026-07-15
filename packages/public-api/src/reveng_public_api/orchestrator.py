"""The pipeline orchestrator.

Chains the nine backend managers exactly as their own APIs require: produce an
``Artifact`` from raw bytes, run static analysis (which persists evidence into
the given ``StorageManager`` internally), build the knowledge graph, derive
reasoning inferences, assemble an investigation case, build and render a
report. No analysis logic lives here -- every step delegates to the owning
backend manager; this module only threads their inputs/outputs together.

Determinism note: given the same input bytes and the same (already
deterministic) backend managers, ``PipelineOrchestrator.run`` produces a
bit-identical ``PipelineResult`` every time. The only non-determinism in this
package lives one layer up, in job/session identity (see ``identifiers.py``)
-- the phase lifecycle events below are the same kind of deliberate, scoped
exception (wall-clock instrumentation only, never part of ``PipelineResult``
itself, so the deterministic output is unaffected).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from reveng_domain_producers import Artifact, ProducerManager, ProducerRequest
from reveng_intermediate_representation import IRModule
from reveng_investigation import InvestigationCase, InvestigationManager
from reveng_knowledge_graph import KnowledgeGraph, KnowledgeGraphManager
from reveng_reasoning import ReasoningManager, ReasoningResult
from reveng_reporting import RenderFormat, Report, ReportingManager
from reveng_static_analysis import AnalysisRequest, StaticAnalysisManager
from reveng_storage_evidence import StorageManager

from .contracts import ClockProtocol
from .identifiers import SystemClock

__all__ = [
    "PipelinePhase",
    "PipelineResult",
    "PhaseStarted",
    "PhaseCompleted",
    "ArtifactProduced",
    "PipelineFailure",
    "PipelineCancelled",
    "PipelineEvent",
    "PipelineEventListener",
    "CancellationRequested",
    "PipelineOrchestrator",
]


class PipelinePhase(str, Enum):
    """The orchestrator's flat phase sequence -- one shared vocabulary used by
    ``Job.current_phase``, every lifecycle event, and every phase-timing key.
    ``(str, Enum)`` so FastAPI/Pydantic serialize it as its plain string value
    on the wire, never as ``"PipelinePhase.REASONING"``."""

    PRODUCER = "producer"
    STATIC_ANALYSIS = "static_analysis"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    REASONING = "reasoning"
    INVESTIGATION = "investigation"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass(frozen=True)
class PipelineResult:
    """The immutable outcome of running the full pipeline over one artifact."""

    artifact_ref: str
    module: IRModule
    report: Report
    rendered: str
    graph: KnowledgeGraph
    reasoning: ReasoningResult
    investigation: InvestigationCase


# -- internal lifecycle events -------------------------------------------------
#
# Used internally only (JobManager subscribes to update Job progress fields in
# real time) -- not part of the public HTTP contract, not re-exported from the
# package's __init__.py.


@dataclass(frozen=True)
class PhaseStarted:
    phase: PipelinePhase
    at: float


@dataclass(frozen=True)
class PhaseCompleted:
    phase: PipelinePhase
    at: float
    elapsed: float


@dataclass(frozen=True)
class ArtifactProduced:
    """Emitted as soon as the artifact ref is known (end of the static-analysis
    phase) -- well before job completion, so in-flight jobs are filterable by
    ``artifact_ref`` too."""

    artifact_ref: str
    at: float


@dataclass(frozen=True)
class PipelineFailure:
    phase: PipelinePhase
    error: str
    at: float


@dataclass(frozen=True)
class PipelineCancelled:
    phase: PipelinePhase
    at: float


PipelineEvent = (
    PhaseStarted | PhaseCompleted | ArtifactProduced | PipelineFailure | PipelineCancelled
)
PipelineEventListener = Callable[[PipelineEvent], None]


class CancellationRequested(Exception):
    """Raised internally when ``cancellation_check()`` reports True at a phase
    boundary. Never escapes ``run()`` uncaught in practice -- ``JobManager``
    catches it specifically to distinguish a cooperative cancel from a genuine
    failure."""


class PipelineOrchestrator:
    """Coordinates the nine backend managers into one end-to-end pipeline run."""

    def __init__(
        self,
        *,
        producers: ProducerManager,
        static_analysis: StaticAnalysisManager,
        storage: StorageManager,
        knowledge_graph: KnowledgeGraphManager,
        reasoning: ReasoningManager,
        investigation: InvestigationManager,
        reporting: ReportingManager,
        clock: ClockProtocol | None = None,
    ) -> None:
        self._producers = producers
        self._static_analysis = static_analysis
        self._storage = storage
        self._knowledge_graph = knowledge_graph
        self._reasoning = reasoning
        self._investigation = investigation
        self._reporting = reporting
        self._clock: ClockProtocol = clock or SystemClock()

    @property
    def storage(self) -> StorageManager:
        """The shared evidence store -- one instance across every job's
        lifetime; callers scope reads to one job via ``Evidence.artifact_ref``."""

        return self._storage

    def produce_artifact(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
    ) -> Artifact:
        request = ProducerRequest(
            content=content, source_ref=source_ref, hint_extension=hint_extension
        )
        return self._producers.produce(request)

    def run(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
        on_event: PipelineEventListener | None = None,
        cancellation_check: Callable[[], bool] | None = None,
    ) -> PipelineResult:
        current_phase = PipelinePhase.PRODUCER

        def emit(event: PipelineEvent) -> None:
            if on_event is not None:
                on_event(event)

        def start(phase: PipelinePhase) -> float:
            nonlocal current_phase
            current_phase = phase
            if cancellation_check is not None and cancellation_check():
                emit(PipelineCancelled(phase=phase, at=self._clock.now()))
                raise CancellationRequested(phase.value)
            started = self._clock.now()
            emit(PhaseStarted(phase=phase, at=started))
            return started

        def finish(phase: PipelinePhase, started: float) -> None:
            now = self._clock.now()
            emit(PhaseCompleted(phase=phase, at=now, elapsed=now - started))

        try:
            started = start(PipelinePhase.PRODUCER)
            artifact = self.produce_artifact(
                content, source_ref=source_ref, hint_extension=hint_extension
            )
            finish(PipelinePhase.PRODUCER, started)

            started = start(PipelinePhase.STATIC_ANALYSIS)
            analysis_request = AnalysisRequest(artifact=artifact, raw_content=content)
            analysis_report = self._static_analysis.analyze(analysis_request, storage=self._storage)
            emit(ArtifactProduced(artifact_ref=analysis_report.artifact_ref, at=self._clock.now()))
            finish(PipelinePhase.STATIC_ANALYSIS, started)

            started = start(PipelinePhase.KNOWLEDGE_GRAPH)
            graph = self._knowledge_graph.build(
                ir_module=analysis_report.module, evidence=analysis_report.evidence
            )
            finish(PipelinePhase.KNOWLEDGE_GRAPH, started)

            started = start(PipelinePhase.REASONING)
            reasoning_result = self._reasoning.run(graph, self._storage.repository)
            finish(PipelinePhase.REASONING, started)

            started = start(PipelinePhase.INVESTIGATION)
            case = self._investigation.build(graph, self._storage.repository, reasoning_result)
            finish(PipelinePhase.INVESTIGATION, started)

            started = start(PipelinePhase.REPORTING)
            report = self._reporting.build(
                case,
                reasoning_result,
                self._storage.repository,
                graph,
                template_name=template_name,
            )
            rendered = self._reporting.render(report, RenderFormat.JSON)
            finish(PipelinePhase.REPORTING, started)
        except CancellationRequested:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
            emit(
                PipelineFailure(
                    phase=current_phase,
                    error=f"{type(exc).__name__}: {exc}",
                    at=self._clock.now(),
                )
            )
            raise

        return PipelineResult(
            artifact_ref=analysis_report.artifact_ref,
            module=analysis_report.module,
            report=report,
            rendered=rendered,
            graph=graph,
            reasoning=reasoning_result,
            investigation=case,
        )
