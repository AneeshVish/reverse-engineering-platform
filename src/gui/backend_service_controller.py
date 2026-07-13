# -*- coding: utf-8 -*-
"""BackendServiceController -- wraps DesktopManager for the Pipeline Workspace.

Owns the Desktop-SDK service lifecycle, health polling, and report-job
submission/polling. Every blocking call (service start, a health check, a
job submission, a status poll) runs on a background ``QThread``, mirroring
the app's existing analysis-worker pattern -- the Qt UI thread never blocks
on backend I/O (Phase 016 spec, 10.13).

Disconnection policy (10.6): on an unreachable backend, polling pauses
(never busy-retries), the controller reports OFFLINE (distinct from
FAILED), and reconnection is both automatic (bounded background interval)
and manual (``reconnect_now()``). Previously-fetched data is never cleared
by a connectivity failure.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal

from src.gui.ui_states import PipelineState

logger = logging.getLogger(__name__)

HEALTH_POLL_INTERVAL_MS = 20_000  # within the spec's 15-30s band
JOB_POLL_INTERVAL_MS = 750
RECONNECT_INTERVAL_MS = 20_000


@dataclass
class JobRecord:
    job_id: str
    source_ref: str
    submitted_at: float
    state: str = "pending"
    error: Optional[str] = None


@dataclass
class _ReportCacheEntry:
    job_id: str
    content: str
    fetched_at: float = field(default_factory=time.time)


class _CallWorker(QThread):
    """Runs one callable off the Qt main thread, emits (result, error)."""

    finished_with_result = pyqtSignal(object, object)  # (result, exc_or_None)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - reported via signal, not raised
            self.finished_with_result.emit(None, exc)
            return
        self.finished_with_result.emit(result, None)


class BackendServiceController(QObject):
    """Composition root the desktop GUI uses to reach the public API."""

    # (PipelineState, HealthResponse | None)
    health_changed = pyqtSignal(object, object)
    initialized = pyqtSignal()
    initialization_failed = pyqtSignal(str)
    job_submitted = pyqtSignal(str)  # job_id
    job_status_changed = pyqtSignal(str, object)  # job_id, JobStatusResponse
    job_report_ready = pyqtSignal(str, str)  # job_id, rendered content
    job_failed = pyqtSignal(str, str)  # job_id, error message
    plugins_ready = pyqtSignal(list)

    def __init__(self, manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._state = PipelineState.NOT_INITIALIZED
        self._last_health = None
        self._recent_jobs: list[JobRecord] = []
        self._report_cache: dict[str, _ReportCacheEntry] = {}
        self._latest_job_id: Optional[str] = None
        self._offline = False
        self._active_workers: list[QThread] = []

        self._health_timer = QTimer(self)
        self._health_timer.setInterval(HEALTH_POLL_INTERVAL_MS)
        self._health_timer.timeout.connect(self.poll_health)

        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setInterval(RECONNECT_INTERVAL_MS)
        self._reconnect_timer.timeout.connect(self._attempt_reconnect)

    # -- lifecycle -----------------------------------------------------------

    def initialize(self) -> None:
        self._set_state(PipelineState.CONNECTING)
        self._run(self._manager.initialize, self._on_initialize_result)

    def _on_initialize_result(self, _result, exc) -> None:
        if exc is not None:
            logger.error("[Pipeline] backend initialize failed: %s", exc)
            self._offline = True
            self._set_state(PipelineState.OFFLINE)
            self.initialization_failed.emit(str(exc))
            self._reconnect_timer.start()
            return
        self._offline = False
        self._set_state(PipelineState.CONNECTED)
        self._health_timer.start()
        self.initialized.emit()
        self.poll_health()

    def shutdown(self) -> None:
        self._health_timer.stop()
        self._reconnect_timer.stop()
        for worker in list(self._active_workers):
            worker.wait(200)
        try:
            self._manager.shutdown()
        except Exception as exc:  # noqa: BLE001 - best-effort shutdown
            logger.error("[Pipeline] backend shutdown error: %s", exc)

    # -- health / disconnection policy ------------------------------------

    @property
    def state(self) -> PipelineState:
        return self._state

    @property
    def last_health(self):
        return self._last_health

    def poll_health(self) -> None:
        if self._offline:
            return  # disconnection policy: never busy-poll while offline
        self._run(self._manager.remote_health, self._on_health_result)

    def reconnect_now(self) -> None:
        """Manual reconnect action exposed on the status strip."""

        self._attempt_reconnect()

    def _attempt_reconnect(self) -> None:
        self._run(self._manager.service.ensure_connected, self._on_reconnect_result)

    def _on_reconnect_result(self, _result, exc) -> None:
        if exc is not None:
            return  # still offline; next timer tick or manual click tries again
        self._offline = False
        self._reconnect_timer.stop()
        self._set_state(PipelineState.CONNECTED)
        if not self._health_timer.isActive():
            self._health_timer.start()
        self.poll_health()

    def _on_health_result(self, result, exc) -> None:
        if exc is not None:
            logger.warning("[Pipeline] health check failed: %s", exc)
            self._offline = True
            self._health_timer.stop()
            self._set_state(PipelineState.OFFLINE)
            self._reconnect_timer.start()
            self.health_changed.emit(self._state, None)
            return
        self._last_health = result
        self._set_state(PipelineState.CONNECTED)
        self.health_changed.emit(self._state, result)

    # -- plugins / extensions -------------------------------------------------

    def refresh_plugins(self) -> None:
        self._run(self._manager.plugins, self._on_plugins_result)

    def _on_plugins_result(self, result, exc) -> None:
        if exc is not None:
            logger.warning("[Pipeline] plugins fetch failed: %s", exc)
            return
        self.plugins_ready.emit(list(result))

    # -- report jobs -----------------------------------------------------------

    @property
    def recent_jobs(self) -> tuple[JobRecord, ...]:
        """Session-scoped only (Phase 016 spec, 10.3) -- not persisted."""

        return tuple(self._recent_jobs)

    @property
    def latest_report(self) -> Optional[str]:
        if self._latest_job_id is None:
            return None
        entry = self._report_cache.get(self._latest_job_id)
        return entry.content if entry else None

    @property
    def latest_job_id(self) -> Optional[str]:
        return self._latest_job_id

    def cached_report(self, job_id: str) -> Optional[str]:
        entry = self._report_cache.get(job_id)
        return entry.content if entry else None

    def generate_report(self, content: bytes, *, source_ref: str) -> None:
        self._set_state(PipelineState.GENERATING)
        self._run(
            lambda: self._manager.submit_artifact(content, source_ref=source_ref),
            self._on_submit_result,
        )

    def _on_submit_result(self, result, exc) -> None:
        if exc is not None:
            self._set_state(PipelineState.FAILED)
            self.job_failed.emit("", str(exc))
            return
        job_id = result.job_id
        self._recent_jobs.insert(
            0, JobRecord(job_id=job_id, source_ref="", submitted_at=time.time())
        )
        self._latest_job_id = job_id
        self.job_submitted.emit(job_id)
        self._poll_job_once(job_id)

    def _poll_job_once(self, job_id: str) -> None:
        self._run(lambda: self._manager.refresh_job(job_id), lambda r, e: self._on_job_poll(job_id, r, e))

    def _on_job_poll(self, job_id: str, result, exc) -> None:
        if exc is not None:
            self._offline = True
            self._set_state(PipelineState.OFFLINE)
            self._mark_job_state(job_id, "offline")
            self._reconnect_timer.start()
            return
        self._mark_job_state(job_id, result.state)
        self.job_status_changed.emit(job_id, result)
        if result.state == "completed":
            self._set_state(PipelineState.COMPLETED)
            self._fetch_report(job_id)
        elif result.state == "failed":
            self._set_state(PipelineState.FAILED)
            self._mark_job_error(job_id, result.error or "job failed")
            self.job_failed.emit(job_id, result.error or "job failed")
        else:
            QTimer.singleShot(JOB_POLL_INTERVAL_MS, lambda: self._poll_job_once(job_id))

    def _mark_job_state(self, job_id: str, state: str) -> None:
        for record in self._recent_jobs:
            if record.job_id == job_id:
                record.state = state
                return

    def _mark_job_error(self, job_id: str, error: str) -> None:
        for record in self._recent_jobs:
            if record.job_id == job_id:
                record.error = error
                return

    def _fetch_report(self, job_id: str) -> None:
        self._run(
            lambda: self._manager.fetch_report(job_id),
            lambda r, e: self._on_report_result(job_id, r, e),
        )

    def _on_report_result(self, job_id: str, result, exc) -> None:
        if exc is not None:
            self.job_failed.emit(job_id, str(exc))
            return
        self._report_cache[job_id] = _ReportCacheEntry(job_id=job_id, content=result.content)
        self._latest_job_id = job_id
        self.job_report_ready.emit(job_id, result.content)

    # -- internal --------------------------------------------------------------

    def _set_state(self, state: PipelineState) -> None:
        self._state = state

    def _run(self, fn, on_done) -> None:
        worker = _CallWorker(fn, parent=self)
        self._active_workers.append(worker)

        def _cleanup(result, exc):
            if worker in self._active_workers:
                self._active_workers.remove(worker)
            on_done(result, exc)

        worker.finished_with_result.connect(_cleanup)
        worker.start()
