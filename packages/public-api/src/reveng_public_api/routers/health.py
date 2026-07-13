"""Health check -- unauthenticated, aggregates every wired component."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ..schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def get_health(request: Request) -> HealthResponse:
    service = request.app.state.service
    result = service.health()
    components = {
        name: component.health().state.value
        for name, component in service.application.components.items()
        if callable(getattr(component, "health", None))
    }
    return HealthResponse(state=result.state.value, detail=result.detail, components=components)
