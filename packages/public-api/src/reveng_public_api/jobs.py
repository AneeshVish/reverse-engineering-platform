"""In-memory job record shape.

``Job`` is the one deliberately mutable shape in this package: it represents
genuinely time-varying state (see ``identifiers.py`` for the scoped
non-determinism exception this reflects). Pure data + state transitions only
-- execution lives in ``job_manager.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .orchestrator import PipelinePhase, PipelineResult

__all__ = ["JobState", "PipelinePhase", "PhaseTiming", "Job"]


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class PhaseTiming:
    """A completed phase's wall-clock timing, recorded as the orchestrator's
    lifecycle events arrive."""

    phase: PipelinePhase
    started_at: float
    completed_at: float
    elapsed: float


@dataclass
class Job:
    """A submitted pipeline run and its current state.

    Mutated in place by the job manager under its lock; callers only ever
    observe snapshots (see ``job_manager._snapshot_job``, which also copies
    the mutable ``phases`` dict), never this live object.
    """

    job_id: str
    state: JobState
    submitted_at: float
    source_ref: str = ""
    started_at: float | None = None
    finished_at: float | None = None
    result: PipelineResult | None = None
    error: str | None = None
    artifact_ref: str | None = None
    current_phase: PipelinePhase | None = None
    phases: dict[PipelinePhase, PhaseTiming] = field(default_factory=dict)
    cancel_requested: bool = False
