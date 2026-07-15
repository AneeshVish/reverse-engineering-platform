"""Job submission, status, history, cancellation, and query routes.

Submission kicks off the full pipeline in the background; status/history reads
are non-blocking snapshots of in-memory job state. The four query routes
(investigation/evidence/reasoning/graph) reuse each backend package's own
canonical serializer -- ``Serializer.serialize(obj)`` -> ``json.loads`` ->
``ResponseModel.model_validate(...)`` -- so the JSON shape returned here is
byte-identical to what that package already deterministically produces.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from reveng_investigation import InvestigationSerializer
from reveng_knowledge_graph import GraphNodeKind, GraphSerializer, KnowledgeGraph
from reveng_reasoning import ReasoningSerializer
from reveng_storage_evidence import EvidenceSerializer

from ..auth import require_principal
from ..errors import JobError, NotFoundError
from ..init import ServiceContext
from ..jobs import Job, JobState
from ..schemas import (
    EvidenceResponse,
    GraphResponse,
    InvestigationResponse,
    JobDetail,
    JobListResponse,
    JobSubmitResponse,
    JobSummary,
    PhaseTimingModel,
    ReasoningResponse,
    ReportResponse,
)

router = APIRouter(prefix="/jobs", tags=["jobs"], dependencies=[Depends(require_principal)])

_TOTAL_PHASES = 6


def _progress_percent(job: Job) -> float:
    if job.state == JobState.COMPLETED:
        return 100.0
    return round(100.0 * len(job.phases) / _TOTAL_PHASES, 2)


def _estimated_remaining(job: Job) -> float | None:
    if job.state != JobState.RUNNING or not job.phases:
        return None
    remaining = _TOTAL_PHASES - len(job.phases)
    if remaining <= 0:
        return 0.0
    average = sum(timing.elapsed for timing in job.phases.values()) / len(job.phases)
    return round(average * remaining, 3)


def _job_summary(job: Job) -> JobSummary:
    return JobSummary(
        job_id=job.job_id,
        state=job.state.value,
        source_ref=job.source_ref,
        artifact_ref=job.artifact_ref,
        submitted_at=job.submitted_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        current_phase=job.current_phase,
        progress_percent=_progress_percent(job),
        error=job.error,
    )


def _job_detail(job: Job) -> JobDetail:
    return JobDetail(
        job_id=job.job_id,
        state=job.state.value,
        submitted_at=job.submitted_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error=job.error,
        source_ref=job.source_ref,
        artifact_ref=job.artifact_ref,
        current_phase=job.current_phase,
        phases=[
            PhaseTimingModel(
                phase=timing.phase,
                started_at=timing.started_at,
                completed_at=timing.completed_at,
                elapsed=timing.elapsed,
            )
            for timing in job.phases.values()
        ],
        progress_percent=_progress_percent(job),
        estimated_remaining=_estimated_remaining(job),
        report_available=job.state == JobState.COMPLETED and job.result is not None,
        cancel_requested=job.cancel_requested,
    )


@router.post("", response_model=JobSubmitResponse, status_code=202)
async def submit_job(
    request: Request,
    file: UploadFile = File(...),
    source_ref: str = Form(...),
    hint_extension: str | None = Form(default=None),
    template_name: str | None = Form(default=None),
) -> JobSubmitResponse:
    service = request.app.state.service
    content = await file.read()

    max_bytes = int(service.config.get("max_upload_bytes"))
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="upload exceeds max_upload_bytes")

    job_id = service.job_manager.submit(
        content,
        source_ref=source_ref,
        hint_extension=hint_extension,
        template_name=template_name,
    )
    return JobSubmitResponse(job_id=job_id)


@router.get("", response_model=JobListResponse)
def list_jobs(
    request: Request,
    state: str | None = Query(default=None),
    project: str | None = Query(
        default=None,
        description="Exact match on the source_ref the desktop tagged the job with "
        "at submission time -- the backend has no native Project entity.",
    ),
    artifact: str | None = Query(default=None, description="Exact match on artifact_ref."),
    created_after: float | None = Query(default=None),
    created_before: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JobListResponse:
    service = request.app.state.service
    parsed_state: JobState | None = None
    if state is not None:
        try:
            parsed_state = JobState(state)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"unknown state: {state}") from exc

    jobs, total_count = service.job_manager.list_jobs(
        state=parsed_state,
        source_ref=project,
        artifact_ref=artifact,
        created_after=created_after,
        created_before=created_before,
        limit=limit,
        offset=offset,
    )
    return JobListResponse(
        jobs=[_job_summary(job) for job in jobs],
        total_count=total_count,
        limit=limit,
        offset=offset,
    )


@router.get("/{job_id}", response_model=JobDetail)
def get_job_status(job_id: str, request: Request) -> JobDetail:
    service = request.app.state.service
    try:
        job = service.job_manager.status(job_id)
    except JobError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return _job_detail(job)


@router.delete("/{job_id}", response_model=JobDetail)
def cancel_job(job_id: str, request: Request) -> JobDetail:
    service = request.app.state.service
    try:
        job = service.job_manager.cancel(job_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except JobError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _job_detail(job)


@router.get("/{job_id}/report", response_model=ReportResponse)
def get_job_report(job_id: str, request: Request) -> ReportResponse:
    service = request.app.state.service
    try:
        job = service.job_manager.status(job_id)
    except JobError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if job.state != JobState.COMPLETED or job.result is None:
        raise HTTPException(
            status_code=409, detail=f"job is not completed (state={job.state.value})"
        )

    return ReportResponse(job_id=job_id, format="json", content=job.result.rendered)


@router.get("/{job_id}/investigation", response_model=InvestigationResponse)
def get_job_investigation(job_id: str, request: Request) -> InvestigationResponse:
    service = request.app.state.service
    job = _require_completed(service, job_id)
    assert job.result is not None
    text = InvestigationSerializer().serialize(job.result.investigation)
    return InvestigationResponse.model_validate(json.loads(text))


@router.get("/{job_id}/evidence", response_model=EvidenceResponse)
def get_job_evidence(job_id: str, request: Request) -> EvidenceResponse:
    service = request.app.state.service
    _require_completed(service, job_id)
    snapshot = service.job_manager.get_evidence(job_id)
    text = EvidenceSerializer().serialize(snapshot)
    return EvidenceResponse.model_validate(json.loads(text))


@router.get("/{job_id}/reasoning", response_model=ReasoningResponse)
def get_job_reasoning(job_id: str, request: Request) -> ReasoningResponse:
    service = request.app.state.service
    job = _require_completed(service, job_id)
    assert job.result is not None
    text = ReasoningSerializer().serialize(job.result.reasoning)
    return ReasoningResponse.model_validate(json.loads(text))


@router.get("/{job_id}/graph", response_model=GraphResponse)
def get_job_graph(
    job_id: str,
    request: Request,
    node_types: str | None = Query(
        default=None, description="Comma-separated GraphNodeKind values to filter nodes by."
    ),
    limit: int | None = Query(
        default=None, ge=1, description="Caps the number of nodes returned, after id-sorting."
    ),
    depth: int | None = Query(
        default=None,
        ge=0,
        description="Reserved for a future seeded-neighborhood query; a no-op today -- "
        "there is no seed-node parameter to expand from and reveng_knowledge_graph has "
        "no traversal primitive. The full filtered+limited graph is returned regardless.",
    ),
) -> GraphResponse:
    service = request.app.state.service
    job = _require_completed(service, job_id)
    assert job.result is not None
    graph = job.result.graph

    nodes = graph.nodes
    if node_types:
        try:
            kinds = {GraphNodeKind(k.strip()) for k in node_types.split(",") if k.strip()}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"unknown node kind: {exc}") from exc
        nodes = tuple(n for n in nodes if n.kind in kinds)
    nodes = tuple(sorted(nodes, key=lambda n: n.id.value))
    if limit is not None:
        nodes = nodes[:limit]

    node_ids = {n.id for n in nodes}
    edges = tuple(e for e in graph.edges if e.source in node_ids and e.target in node_ids)
    filtered = KnowledgeGraph(nodes=nodes, edges=edges, version=graph.version)

    text = GraphSerializer().serialize(filtered)
    return GraphResponse.model_validate(json.loads(text))


def _require_completed(service: ServiceContext, job_id: str) -> Job:
    try:
        job = service.job_manager.status(job_id)
    except JobError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if job.state != JobState.COMPLETED or job.result is None:
        raise HTTPException(
            status_code=409, detail=f"job is not completed (state={job.state.value})"
        )
    return job
