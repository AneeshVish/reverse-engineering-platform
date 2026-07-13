"""Construction helper for the static-analysis manager."""

from __future__ import annotations

from .config import StaticAnalysisConfig, load_static_config
from .manager import StaticAnalysisManager

__all__ = ["build_static_analysis"]


def build_static_analysis(config: StaticAnalysisConfig | None = None) -> StaticAnalysisManager:
    """Construct a ``StaticAnalysisManager`` with resolved configuration."""

    return StaticAnalysisManager(config=config or load_static_config())
