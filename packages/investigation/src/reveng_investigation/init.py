"""Construction helper for the investigation manager."""

from __future__ import annotations

from .config import InvestigationConfig, load_investigation_config
from .manager import InvestigationManager

__all__ = ["build_investigation_manager"]


def build_investigation_manager(
    config: InvestigationConfig | None = None,
) -> InvestigationManager:
    """Construct an ``InvestigationManager`` with resolved configuration."""

    return InvestigationManager(config=config or load_investigation_config())
