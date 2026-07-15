"""Request/response schemas for the HTTP surface.

Pydantic models only — no logic. FastAPI validates incoming request bodies
against these automatically; malformed input never reaches a router body.

The four query-route response models (``InvestigationResponse``,
``EvidenceResponse``, ``ReasoningResponse``, ``GraphResponse``) mirror their
owning package's own canonical serializer JSON shape field-for-field — routes
build them via ``Serializer.serialize(obj)`` -> ``json.loads`` ->
``Model.model_validate(...)``, reusing each package's proven, deterministic
serialization rather than re-implementing it here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .jobs import PipelinePhase

__all__ = [
    "UploadResponse",
    "JobSubmitResponse",
    "JobStatusResponse",
    "PhaseTimingModel",
    "JobSummary",
    "JobDetail",
    "JobListResponse",
    "ReportResponse",
    "PluginSummary",
    "HealthResponse",
    "FindingExplanationModel",
    "FindingModel",
    "InvestigationResponse",
    "EvidenceOriginModel",
    "EvidenceRecordModel",
    "EvidenceResponse",
    "InferenceExplanationModel",
    "InferenceModel",
    "ReasoningResponse",
    "GraphNodeModel",
    "GraphEdgeModel",
    "GraphResponse",
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


class PhaseTimingModel(BaseModel):
    phase: PipelinePhase
    started_at: float
    completed_at: float
    elapsed: float


class JobSummary(BaseModel):
    """One row of ``GET /jobs``."""

    job_id: str
    state: str
    source_ref: str
    artifact_ref: str | None = None
    submitted_at: float
    started_at: float | None = None
    finished_at: float | None = None
    current_phase: PipelinePhase | None = None
    progress_percent: float
    error: str | None = None


class JobDetail(BaseModel):
    """``GET /jobs/{id}`` -- a superset of ``JobStatusResponse``'s fields (same
    names/types, nothing removed) plus richer lifecycle/progress data."""

    job_id: str
    state: str
    submitted_at: float
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    source_ref: str
    artifact_ref: str | None = None
    current_phase: PipelinePhase | None = None
    phases: list[PhaseTimingModel]
    progress_percent: float
    estimated_remaining: float | None = None
    report_available: bool
    cancel_requested: bool


class JobListResponse(BaseModel):
    jobs: list[JobSummary]
    total_count: int
    limit: int
    offset: int


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


# -- investigation ------------------------------------------------------------


class FindingExplanationModel(BaseModel):
    inference_ids: list[str]
    evidence_ids: list[str]
    node_ids: list[str]
    edge_ids: list[str]


class FindingModel(BaseModel):
    id: str
    kind: str
    severity: str
    subject: str
    title: str
    explanation: FindingExplanationModel
    properties: dict[str, Any]


class InvestigationResponse(BaseModel):
    id: str
    status: str
    priority: str
    title: str
    findings: list[FindingModel]
    properties: dict[str, Any]


# -- evidence -------------------------------------------------------------


class EvidenceOriginModel(BaseModel):
    origin_kind: str
    reference: str


class EvidenceRecordModel(BaseModel):
    id: str
    kind: str
    state: str
    origin: EvidenceOriginModel
    confidence: str
    payload: Any = None
    ir_refs: list[str]
    artifact_ref: str
    metadata: dict[str, Any]
    version: int


class EvidenceResponse(BaseModel):
    evidence: list[EvidenceRecordModel]


# -- reasoning -------------------------------------------------------------


class InferenceExplanationModel(BaseModel):
    rule_id: str
    output_fact: str
    input_evidence: list[str]
    input_nodes: list[str]
    input_edges: list[str]


class InferenceModel(BaseModel):
    id: str
    kind: str
    state: str
    subject: str
    fact: str
    explanation: InferenceExplanationModel
    properties: dict[str, Any]


class ReasoningResponse(BaseModel):
    inferences: list[InferenceModel]


# -- graph -------------------------------------------------------------


class GraphNodeModel(BaseModel):
    id: str
    kind: str
    logical_key: str
    name: str
    properties: dict[str, Any]


class GraphEdgeModel(BaseModel):
    id: str
    relationship: str
    source: str
    target: str
    properties: dict[str, Any]


class GraphResponse(BaseModel):
    version: int
    nodes: list[GraphNodeModel]
    edges: list[GraphEdgeModel]
