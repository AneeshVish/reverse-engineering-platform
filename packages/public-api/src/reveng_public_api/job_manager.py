"""Background-thread job execution.

Submitting a job returns immediately with a job id; a bounded thread pool runs
the (synchronous) pipeline orchestrator; status/result reads are non-blocking
snapshots of in-memory job state guarded by a single lock. Every individual
backend call inside a job's thread body stays synchronous, matching every
backend package's own "sync only" contract -- concurrency exists only at the
job-scheduling layer, not inside any one job's execution.

Job history is the same in-memory dict, never pruned and queryable with
filters (``JobHistoryStore``) -- not a new persistence backend; jobs remain
in-memory for the process lifetime, matching this platform's existing
"no database introduced at this layer" discipline.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from reveng_core_substrate import HealthAggregator, HealthResult, HealthState
from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import RepositorySnapshot

from .contracts import ClockProtocol, IdProvider
from .errors import JobError, NotFoundError
from .identifiers import MonotonicIdProvider, SystemClock
from .jobs import Job, JobState, PhaseTiming, PipelinePhase
from .orchestrator import (
    ArtifactProduced,
    CancellationRequested,
    PhaseCompleted,
    PhaseStarted,
    PipelineEvent,
    PipelineOrchestrator,
    PipelineResult,
)

__all__ = ["JobManager"]


def _snapshot_job(job: Job) -> Job:
    """A true point-in-time copy of a live ``Job``.

    ``dataclasses.replace`` alone is shallow -- it would share the mutable
    ``phases`` dict with the live record the worker thread keeps inserting
    into, so a caller iterating the "snapshot" could race a phase-completion
    write. Copying ``phases`` (whose values are frozen ``PhaseTiming``s)
    restores the snapshot guarantee the ``Job`` docstring promises.
    """

    return dataclasses.replace(job, phases=dict(job.phases))


class JobHistoryStore:
    """Thin, factored-out query layer over the job manager's in-memory job
    dict -- filtering, newest-first ordering, and pagination live here so
    ``JobManager`` stays a thin scheduling/execution coordinator."""

    def __init__(self, jobs: dict[str, Job], lock: threading.Lock) -> None:
        self._jobs = jobs
        self._lock = lock

    def list_jobs(
        self,
        *,
        state: JobState | None = None,
        source_ref: str | None = None,
        artifact_ref: str | None = None,
        created_after: float | None = None,
        created_before: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[tuple[Job, ...], int]:
        """Newest-first by ``submitted_at``. Returns ``(page, total_count)``."""

        with self._lock:
            snapshot = [_snapshot_job(job) for job in self._jobs.values()]

        def matches(job: Job) -> bool:
            if state is not None and job.state != state:
                return False
            if source_ref is not None and job.source_ref != source_ref:
                return False
            if artifact_ref is not None and job.artifact_ref != artifact_ref:
                return False
            if created_after is not None and job.submitted_at < created_after:
                return False
            if created_before is not None and job.submitted_at > created_before:
                return False
            return True

        filtered = sorted(
            (job for job in snapshot if matches(job)),
            key=lambda job: job.submitted_at,
            reverse=True,
        )
        total_count = len(filtered)
        page = tuple(filtered[offset : offset + limit])
        return page, total_count


class JobManager:
    """Lifecycle-aware coordinator over background pipeline job execution."""

    component_name = "public-api.job-manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        orchestrator: PipelineOrchestrator,
        *,
        max_workers: int = 4,
        id_provider: IdProvider | None = None,
        clock: ClockProtocol | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._max_workers = max_workers
        self._id_provider: IdProvider = id_provider or MonotonicIdProvider()
        self._clock: ClockProtocol = clock or SystemClock()
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._history = JobHistoryStore(self._jobs, self._lock)
        self._executor: ThreadPoolExecutor | None = None

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._executor = None

    # -- submission & access --------------------------------------------------

    def submit(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> str:
        if self._executor is None:
            raise JobError("job manager is not initialized")

        job_id = self._id_provider.new_id("job")
        with self._lock:
            self._jobs[job_id] = Job(
                job_id=job_id,
                state=JobState.PENDING,
                submitted_at=self._clock.now(),
                source_ref=source_ref,
            )
        self._executor.submit(
            self._run_job, job_id, content, source_ref, hint_extension, template_name
        )
        return job_id

    def status(self, job_id: str) -> Job:
        return self._snapshot(job_id)

    def result(self, job_id: str) -> PipelineResult:
        return self._completed_result(job_id)

    def list_jobs(
        self,
        *,
        state: JobState | None = None,
        source_ref: str | None = None,
        artifact_ref: str | None = None,
        created_after: float | None = None,
        created_before: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[tuple[Job, ...], int]:
        return self._history.list_jobs(
            state=state,
            source_ref=source_ref,
            artifact_ref=artifact_ref,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            offset=offset,
        )

    def cancel(self, job_id: str) -> Job:
        """Pending -> Cancelled immediately. Running -> ``cancel_requested``
        set, observed cooperatively at the orchestrator's next phase boundary.
        Unknown job -> ``NotFoundError`` (404); terminal states
        (Completed/Failed/Cancelled) -> ``JobError`` (409)."""

        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise NotFoundError("job not found", job_id=job_id)
            if job.state == JobState.PENDING:
                job.state = JobState.CANCELLED
                job.finished_at = self._clock.now()
            elif job.state == JobState.RUNNING:
                job.cancel_requested = True
            else:
                raise JobError(
                    "job is already in a terminal state", job_id=job_id, state=job.state.value
                )
            return _snapshot_job(job)

    # -- query accessors (job must be COMPLETED) ------------------------------

    def get_investigation(self, job_id: str) -> InvestigationCase:
        return self._completed_result(job_id).investigation

    def get_reasoning(self, job_id: str) -> ReasoningResult:
        return self._completed_result(job_id).reasoning

    def get_graph(self, job_id: str) -> KnowledgeGraph:
        return self._completed_result(job_id).graph

    def get_evidence(self, job_id: str) -> RepositorySnapshot:
        """The requesting job's own evidence, filtered from the shared
        repository (one ``EvidenceRepository`` instance backs every job)."""

        result = self._completed_result(job_id)
        matching = tuple(
            e
            for e in self._orchestrator.storage.repository.enumerate()
            if e.artifact_ref == result.artifact_ref
        )
        return RepositorySnapshot(matching)

    def _completed_result(self, job_id: str) -> PipelineResult:
        job = self._snapshot(job_id)
        if job.state != JobState.COMPLETED or job.result is None:
            raise JobError("job is not completed", job_id=job_id, state=job.state.value)
        return job.result

    def _snapshot(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobError("job not found", job_id=job_id)
            return _snapshot_job(job)

    def _update(self, job_id: str, mutate: Callable[[Job], None]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                mutate(job)

    def _run_job(
        self,
        job_id: str,
        content: bytes,
        source_ref: str,
        hint_extension: str | None,
        template_name: str | None,
    ) -> None:
        started_while_pending_cancel = False

        def mark_running(job: Job) -> None:
            nonlocal started_while_pending_cancel
            if job.state == JobState.CANCELLED:
                started_while_pending_cancel = True
                return
            job.state = JobState.RUNNING
            job.started_at = self._clock.now()

        self._update(job_id, mark_running)
        if started_while_pending_cancel:
            return

        def on_event(event: PipelineEvent) -> None:
            def apply(job: Job) -> None:
                if isinstance(event, PhaseStarted):
                    job.current_phase = event.phase
                elif isinstance(event, PhaseCompleted):
                    job.phases[event.phase] = PhaseTiming(
                        phase=event.phase,
                        started_at=event.at - event.elapsed,
                        completed_at=event.at,
                        elapsed=event.elapsed,
                    )
                elif isinstance(event, ArtifactProduced):
                    job.artifact_ref = event.artifact_ref

            self._update(job_id, apply)

        def cancellation_check() -> bool:
            return self._snapshot(job_id).cancel_requested

        try:
            result = self._orchestrator.run(
                content,
                source_ref=source_ref,
                hint_extension=hint_extension,
                template_name=template_name,
                on_event=on_event,
                cancellation_check=cancellation_check,
            )
        except CancellationRequested:

            def mark_cancelled(job: Job) -> None:
                job.state = JobState.CANCELLED
                job.finished_at = self._clock.now()

            self._update(job_id, mark_cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - deliberate job-boundary conversion
            error_message = f"{type(exc).__name__}: {exc}"

            def mark_failed(job: Job) -> None:
                job.state = JobState.FAILED
                job.error = error_message
                job.finished_at = self._clock.now()

            self._update(job_id, mark_failed)
            return

        def mark_completed(job: Job) -> None:
            job.state = JobState.COMPLETED
            job.result = result
            job.artifact_ref = result.artifact_ref
            job.current_phase = PipelinePhase.COMPLETED
            job.finished_at = self._clock.now()

        self._update(job_id, mark_completed)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        with self._lock:
            total = len(self._jobs)
            failed = sum(1 for j in self._jobs.values() if j.state == JobState.FAILED)
        aggregator = HealthAggregator()
        pool_alive = self._executor is not None
        aggregator.register(
            "pool",
            lambda: HealthResult(
                HealthState.HEALTHY if pool_alive else HealthState.UNHEALTHY,
                detail="pool alive" if pool_alive else "pool not initialized",
            ),
        )
        overall = aggregator.evaluate().overall
        return HealthResult(overall, detail=f"{total} jobs ({failed} failed)")

    def health_state(self) -> HealthState:
        return self.health().state
