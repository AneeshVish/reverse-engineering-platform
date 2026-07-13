"""Read-only plugin listing."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..auth import require_principal
from ..plugins_view import list_plugins
from ..schemas import PluginSummary

router = APIRouter(prefix="/plugins", tags=["plugins"], dependencies=[Depends(require_principal)])


@router.get("", response_model=list[PluginSummary])
def get_plugins(request: Request) -> list[PluginSummary]:
    service = request.app.state.service
    return list(list_plugins(service.plugin_manager))
