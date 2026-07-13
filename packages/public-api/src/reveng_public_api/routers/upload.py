"""Upload endpoint: identifies/produces an ``Artifact`` from raw bytes only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from ..auth import require_principal
from ..schemas import UploadResponse

router = APIRouter(prefix="/artifacts", tags=["artifacts"], dependencies=[Depends(require_principal)])


@router.post("", response_model=UploadResponse, status_code=201)
async def upload_artifact(
    request: Request,
    file: UploadFile = File(...),
    source_ref: str = Form(...),
    hint_extension: str | None = Form(default=None),
) -> UploadResponse:
    service = request.app.state.service
    content = await file.read()

    max_bytes = int(service.config.get("max_upload_bytes"))
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="upload exceeds max_upload_bytes")

    try:
        artifact = service.orchestrator.produce_artifact(
            content, source_ref=source_ref, hint_extension=hint_extension
        )
    except Exception as exc:  # noqa: BLE001 - route boundary, converted to a 4xx
        raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    return UploadResponse(
        artifact_ref=artifact.identity.content_hash, artifact_type=artifact.artifact_type.value
    )
