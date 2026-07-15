"""Desktop IPC abstraction.

Only wraps ``DesktopClient``. Future phases may replace the transport (e.g. a
native IPC channel) by supplying a different ``IPCProtocol`` implementation
without touching callers -- mirrors ``reveng_public_api.auth``'s
``AuthHook``/``AllowAllAuthHook`` seam pattern.
"""

from __future__ import annotations

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

from .client import DesktopClient

__all__ = ["HttpIPC"]


class HttpIPC:
    """The only concrete ``IPCProtocol`` implementation this phase: pure
    delegation to a ``DesktopClient`` over HTTP."""

    def __init__(self, client: DesktopClient) -> None:
        self._client = client

    def upload(
        self, content: bytes, *, source_ref: str, hint_extension: str | None = None
    ) -> UploadResponse:
        return self._client.upload(content, source_ref=source_ref, hint_extension=hint_extension)

    def submit_job(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> JobSubmitResponse:
        return self._client.submit_job(
            content,
            source_ref=source_ref,
            hint_extension=hint_extension,
            template_name=template_name,
        )

    def job_status(self, job_id: str) -> JobStatusResponse:
        return self._client.job_status(job_id)

    def get_job(self, job_id: str) -> JobDetail:
        return self._client.get_job(job_id)

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
    ) -> JobListResponse:
        return self._client.list_jobs(
            state=state,
            source_ref=source_ref,
            artifact_ref=artifact_ref,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            offset=offset,
        )

    def cancel_job(self, job_id: str) -> JobDetail:
        return self._client.cancel_job(job_id)

    def job_report(self, job_id: str) -> ReportResponse:
        return self._client.job_report(job_id)

    def get_investigation(self, job_id: str) -> InvestigationResponse:
        return self._client.get_investigation(job_id)

    def get_evidence(self, job_id: str) -> EvidenceResponse:
        return self._client.get_evidence(job_id)

    def get_reasoning(self, job_id: str) -> ReasoningResponse:
        return self._client.get_reasoning(job_id)

    def get_graph(
        self,
        job_id: str,
        *,
        limit: int | None = None,
        depth: int | None = None,
        node_types: str | None = None,
    ) -> GraphResponse:
        return self._client.get_graph(job_id, limit=limit, depth=depth, node_types=node_types)

    def plugins(self) -> list[PluginSummary]:
        return self._client.plugins()

    def health(self) -> HealthResponse:
        return self._client.health()
