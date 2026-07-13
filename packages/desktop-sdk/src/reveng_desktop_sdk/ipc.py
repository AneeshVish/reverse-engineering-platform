"""Desktop IPC abstraction.

Only wraps ``DesktopClient``. Future phases may replace the transport (e.g. a
native IPC channel) by supplying a different ``IPCProtocol`` implementation
without touching callers -- mirrors ``reveng_public_api.auth``'s
``AuthHook``/``AllowAllAuthHook`` seam pattern.
"""

from __future__ import annotations

from reveng_public_api import (
    HealthResponse,
    JobStatusResponse,
    JobSubmitResponse,
    PluginSummary,
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

    def job_report(self, job_id: str) -> ReportResponse:
        return self._client.job_report(job_id)

    def plugins(self) -> list[PluginSummary]:
        return self._client.plugins()

    def health(self) -> HealthResponse:
        return self._client.health()
