"""Construction helper for the reasoning engine manager."""

from __future__ import annotations

from .config import ReasoningConfig, load_reasoning_config
from .manager import ReasoningManager

__all__ = ["build_reasoning_engine"]


def build_reasoning_engine(config: ReasoningConfig | None = None) -> ReasoningManager:
    """Construct a ``ReasoningManager`` with resolved configuration."""

    return ReasoningManager(config=config or load_reasoning_config())
