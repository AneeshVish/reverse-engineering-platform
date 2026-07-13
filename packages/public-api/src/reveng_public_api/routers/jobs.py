"""Job submission, status, and report retrieval.

Submission kicks off the full pipeline in the background; status/report reads
are non-blocking snapshots of in-memory job state.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from ..auth import require_principal
from ..errors import JobError
from ..jobs import JobState
from ..schemas import JobStatusResponse, JobSubmitResponse, ReportResponse

router = APIRouter(prefix="/jobs", tags=["jobs"], dependencies=[Depends(require_principal)])


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


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str, request: Request) -> JobStatusResponse:
    service = request.app.state.service
    try:
        job = service.job_manager.status(job_id)
    except JobError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return JobStatusResponse(
        job_id=job.job_id,
        state=job.state.value,
        submitted_at=job.submitted_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error=job.error,
    )


@router.get("/{job_id}/report", response_model=ReportResponse)
def get_job_report(job_id: str, request: Request) -> ReportResponse:
    service = request.app.state.service
    try:
        job = service.job_manager.status(job_id)
    except JobError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if job.state != JobState.COMPLETED or job.result is None:
        raise HTTPException(status_code=409, detail=f"job is not completed (state={job.state.value})")

    return ReportResponse(job_id=job_id, format="json", content=job.result.rendered)
