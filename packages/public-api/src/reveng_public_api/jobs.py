"""In-memory job record shape.

``Job`` is the one deliberately mutable shape in this package: it represents
genuinely time-varying state (see ``identifiers.py`` for the scoped
non-determinism exception this reflects). Pure data + state transitions only
-- execution lives in ``job_manager.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .orchestrator import PipelineResult

__all__ = ["JobState", "Job"]


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Job:
    """A submitted pipeline run and its current state.

    Mutated in place by the job manager under its lock; callers only ever
    observe snapshots (``dataclasses.replace``), never this live object.
    """

    job_id: str
    state: JobState
    submitted_at: float
    started_at: float | None = None
    finished_at: float | None = None
    result: PipelineResult | None = None
    error: str | None = None
