"""Typed HTTP client over the public API's REST endpoints.

No business logic: each method maps 1:1 onto one public-api route and returns
that route's own Pydantic response model directly (``reveng_public_api`` is
this package's one allowed import, so re-declaring parallel DTOs would only
add drift risk, not real decoupling). Sync only -- this is a thin I/O client
with no stated concurrency need, and every composition root in this
codebase is sync. Phase 014 shipped the original six endpoints (upload,
submit/status/report a job, list plugins, health); Phase 017 added job
history/cancellation and the investigation/evidence/reasoning/graph query
routes, additively.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
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

from .errors import (
    JobNotReadyError,
    NotFoundError,
    RequestError,
    ServiceError,
    ServiceUnavailableError,
)

__all__ = ["DesktopClient"]

DEFAULT_BASE_URL = "http://127.0.0.1:8000"

_TERMINAL_STATES = ("completed", "failed", "cancelled")


class DesktopClient:
    """Sync, typed wrapper over the public API's REST endpoints."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = 10.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._http = http_client or httpx.Client(base_url=base_url, timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> DesktopClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def upload(
        self, content: bytes, *, source_ref: str, hint_extension: str | None = None
    ) -> UploadResponse:
        data = {"source_ref": source_ref}
        if hint_extension is not None:
            data["hint_extension"] = hint_extension
        response = self._request(
            "POST", "/artifacts", files={"file": ("upload.bin", content)}, data=data
        )
        return UploadResponse.model_validate(response.json())

    def submit_job(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> JobSubmitResponse:
        data = {"source_ref": source_ref}
        if hint_extension is not None:
            data["hint_extension"] = hint_extension
        if template_name is not None:
            data["template_name"] = template_name
        response = self._request(
            "POST", "/jobs", files={"file": ("upload.bin", content)}, data=data
        )
        return JobSubmitResponse.model_validate(response.json())

    def job_status(self, job_id: str) -> JobStatusResponse:
        response = self._request("GET", f"/jobs/{job_id}")
        return JobStatusResponse.model_validate(response.json())

    def get_job(self, job_id: str) -> JobDetail:
        """Richer job detail than ``job_status`` -- source_ref, artifact_ref,
        current phase, per-phase timings, progress, and cancellation state."""

        response = self._request("GET", f"/jobs/{job_id}")
        return JobDetail.model_validate(response.json())

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
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if state is not None:
            params["state"] = state
        if source_ref is not None:
            params["project"] = source_ref
        if artifact_ref is not None:
            params["artifact"] = artifact_ref
        if created_after is not None:
            params["created_after"] = created_after
        if created_before is not None:
            params["created_before"] = created_before
        response = self._request("GET", "/jobs", params=params)
        return JobListResponse.model_validate(response.json())

    def cancel_job(self, job_id: str) -> JobDetail:
        response = self._request("DELETE", f"/jobs/{job_id}")
        return JobDetail.model_validate(response.json())

    def job_report(self, job_id: str) -> ReportResponse:
        response = self._request("GET", f"/jobs/{job_id}/report")
        return ReportResponse.model_validate(response.json())

    def get_investigation(self, job_id: str) -> InvestigationResponse:
        response = self._request("GET", f"/jobs/{job_id}/investigation")
        return InvestigationResponse.model_validate(response.json())

    def get_evidence(self, job_id: str) -> EvidenceResponse:
        response = self._request("GET", f"/jobs/{job_id}/evidence")
        return EvidenceResponse.model_validate(response.json())

    def get_reasoning(self, job_id: str) -> ReasoningResponse:
        response = self._request("GET", f"/jobs/{job_id}/reasoning")
        return ReasoningResponse.model_validate(response.json())

    def get_graph(
        self,
        job_id: str,
        *,
        limit: int | None = None,
        depth: int | None = None,
        node_types: str | None = None,
    ) -> GraphResponse:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if depth is not None:
            params["depth"] = depth
        if node_types is not None:
            params["node_types"] = node_types
        response = self._request("GET", f"/jobs/{job_id}/graph", params=params)
        return GraphResponse.model_validate(response.json())

    def plugins(self) -> list[PluginSummary]:
        response = self._request("GET", "/plugins")
        return [PluginSummary.model_validate(item) for item in response.json()]

    def health(self) -> HealthResponse:
        response = self._request("GET", "/health")
        return HealthResponse.model_validate(response.json())

    def poll_job(
        self, job_id: str, *, interval: float = 0.5, timeout: float = 60.0
    ) -> JobStatusResponse:
        """Block until the job reaches a terminal state, or raise on timeout."""

        deadline = time.monotonic() + timeout
        status = self.job_status(job_id)
        while status.state not in _TERMINAL_STATES:
            if time.monotonic() >= deadline:
                raise RequestError(
                    "job did not reach a terminal state before timeout",
                    job_id=job_id,
                    state=status.state,
                )
            time.sleep(interval)
            status = self.job_status(job_id)
        return status

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.TransportError as exc:
            raise ServiceUnavailableError(
                "could not reach the public API service", path=path
            ) from exc

        if response.status_code == 404:
            raise NotFoundError("resource not found", path=path)
        if response.status_code == 409:
            raise JobNotReadyError("job is not completed", path=path)
        if response.status_code in (413, 422):
            raise RequestError(
                "the server rejected the request",
                path=path,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise ServiceError(
                "unexpected server error", path=path, status_code=response.status_code
            )
        return response
