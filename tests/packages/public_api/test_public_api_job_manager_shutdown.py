"""Public-api tests: JobManager.shutdown() waits for in-flight jobs."""

from __future__ import annotations

import threading

from _public_api_helpers import TEST_ARTIFACT_BYTES
from reveng_domain_producers import ProducerManager, ProducerRegistry
from reveng_investigation import InvestigationManager
from reveng_knowledge_graph import KnowledgeGraphManager
from reveng_public_api import JobManager, JobState, PipelineOrchestrator
from reveng_reasoning import ReasoningManager
from reveng_reporting import ReportingManager
from reveng_static_analysis import StaticAnalysisManager
from reveng_storage_evidence import StorageManager


class _GatedStaticAnalysis(StaticAnalysisManager):
    """Blocks inside analyze() until released, to make in-flight state observable."""

    def __init__(self, gate: threading.Event) -> None:
        super().__init__()
        self._gate = gate

    def analyze(self, request, *, storage=None):  # type: ignore[override]
        self._gate.wait(timeout=5.0)
        return super().analyze(request, storage=storage)


def test_shutdown_waits_for_in_flight_job() -> None:
    gate = threading.Event()
    producers = ProducerManager(ProducerRegistry())
    producers.initialize()
    static_analysis = _GatedStaticAnalysis(gate)
    static_analysis.initialize()

    orchestrator = PipelineOrchestrator(
        producers=producers,
        static_analysis=static_analysis,
        storage=StorageManager(),
        knowledge_graph=KnowledgeGraphManager(),
        reasoning=ReasoningManager(),
        investigation=InvestigationManager(),
        reporting=ReportingManager(),
    )
    job_manager = JobManager(orchestrator, max_workers=1)
    job_manager.initialize()

    job_id = job_manager.submit(TEST_ARTIFACT_BYTES, source_ref="gated")

    shutdown_thread = threading.Thread(target=job_manager.shutdown)
    shutdown_thread.start()

    # Release the gate only after shutdown() has had a moment to start waiting.
    threading.Event().wait(timeout=0.05)
    gate.set()
    shutdown_thread.join(timeout=5.0)

    assert not shutdown_thread.is_alive()
    assert job_manager.status(job_id).state in (JobState.COMPLETED, JobState.FAILED)
