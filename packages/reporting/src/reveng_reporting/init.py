"""Construction helper for the reporting manager."""

from __future__ import annotations

from .config import ReportingConfig, load_reporting_config
from .manager import ReportingManager

__all__ = ["build_reporting_manager"]


def build_reporting_manager(config: ReportingConfig | None = None) -> ReportingManager:
    """Construct a ``ReportingManager`` with resolved configuration."""

    return ReportingManager(config=config or load_reporting_config())
