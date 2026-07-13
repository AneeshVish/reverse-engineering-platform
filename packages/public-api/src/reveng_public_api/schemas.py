"""Request/response schemas for the HTTP surface.

Pydantic models only — no logic. FastAPI validates incoming request bodies
against these automatically; malformed input never reaches a router body.
"""

from __future__ import annotations

from pydantic import BaseModel

__all__ = [
    "UploadResponse",
    "JobSubmitResponse",
    "JobStatusResponse",
    "ReportResponse",
    "PluginSummary",
    "HealthResponse",
]


class UploadResponse(BaseModel):
    artifact_ref: str
    artifact_type: str


class JobSubmitResponse(BaseModel):
    job_id: str


class JobStatusResponse(BaseModel):
    job_id: str
    state: str
    submitted_at: float
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None


class ReportResponse(BaseModel):
    job_id: str
    format: str
    content: str


class PluginSummary(BaseModel):
    identifier: str
    name: str
    capabilities: list[str]


class HealthResponse(BaseModel):
    state: str
    detail: str
    components: dict[str, str]
