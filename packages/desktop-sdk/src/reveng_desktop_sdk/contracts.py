"""Protocol definitions for the desktop-IPC transport seam.

``IPCProtocol`` is the abstraction ``ipc.py`` implements; future phases may
supply a different transport (e.g. a native IPC channel) without touching
callers that only depend on this protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reveng_public_api import (
    EvidenceResponse,
    GraphResponse,
    HealthResponse,
    InvestigationResponse,
    JobDetail,
    JobListResponse,
    JobStatusResponse,
    JobSubmitResponse,
    PluginSummary,
    ReasoningResponse,
    ReportResponse,
    UploadResponse,
)

__all__ = ["IPCProtocol"]


@runtime_checkable
class IPCProtocol(Protocol):
    """The desktop-facing operations the manager needs from any transport."""

    def upload(
        self, content: bytes, *, source_ref: str, hint_extension: str | None = None
    ) -> UploadResponse: ...

    def submit_job(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> JobSubmitResponse: ...

    def job_status(self, job_id: str) -> JobStatusResponse: ...

    def get_job(self, job_id: str) -> JobDetail: ...

    def list_jobs(
        self,
        *,
        state: str | None = None,
        source_ref: str | None = None,
        artifact_ref: str | None = None,
        created_after: float | None = None,
        created_before: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> JobListResponse: ...

    def cancel_job(self, job_id: str) -> JobDetail: ...

    def job_report(self, job_id: str) -> ReportResponse: ...

    def get_investigation(self, job_id: str) -> InvestigationResponse: ...

    def get_evidence(self, job_id: str) -> EvidenceResponse: ...

    def get_reasoning(self, job_id: str) -> ReasoningResponse: ...

    def get_graph(
        self,
        job_id: str,
        *,
        limit: int | None = None,
        depth: int | None = None,
        node_types: str | None = None,
    ) -> GraphResponse: ...

    def plugins(self) -> list[PluginSummary]: ...

    def health(self) -> HealthResponse: ...
