"""Background-thread job execution.

Submitting a job returns immediately with a job id; a bounded thread pool runs
the (synchronous) pipeline orchestrator; status/result reads are non-blocking
snapshots of in-memory job state guarded by a single lock. Every individual
backend call inside a job's thread body stays synchronous, matching every
backend package's own "sync only" contract -- concurrency exists only at the
job-scheduling layer, not inside any one job's execution.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from reveng_core_substrate import HealthAggregator, HealthResult, HealthState

from .contracts import ClockProtocol, IdProvider
from .errors import JobError
from .identifiers import MonotonicIdProvider, SystemClock
from .jobs import Job, JobState
from .orchestrator import PipelineOrchestrator, PipelineResult

__all__ = ["JobManager"]


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
                job_id=job_id, state=JobState.PENDING, submitted_at=self._clock.now()
            )
        self._executor.submit(
            self._run_job, job_id, content, source_ref, hint_extension, template_name
        )
        return job_id

    def status(self, job_id: str) -> Job:
        return self._snapshot(job_id)

    def result(self, job_id: str) -> PipelineResult:
        job = self._snapshot(job_id)
        if job.state != JobState.COMPLETED or job.result is None:
            raise JobError("job is not completed", job_id=job_id, state=job.state.value)
        return job.result

    def _snapshot(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobError("job not found", job_id=job_id)
            return dataclasses.replace(job)

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
        def mark_running(job: Job) -> None:
            job.state = JobState.RUNNING
            job.started_at = self._clock.now()

        self._update(job_id, mark_running)

        try:
            result = self._orchestrator.run(
                content,
                source_ref=source_ref,
                hint_extension=hint_extension,
                template_name=template_name,
            )
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
