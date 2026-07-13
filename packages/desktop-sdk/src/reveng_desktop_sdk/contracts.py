"""Protocol definitions for the desktop-IPC transport seam.

``IPCProtocol`` is the abstraction ``ipc.py`` implements; future phases may
supply a different transport (e.g. a native IPC channel) without touching
callers that only depend on this protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from reveng_public_api import (
    HealthResponse,
    JobStatusResponse,
    JobSubmitResponse,
    PluginSummary,
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

    def job_report(self, job_id: str) -> ReportResponse: ...

    def plugins(self) -> list[PluginSummary]: ...

    def health(self) -> HealthResponse: ...
