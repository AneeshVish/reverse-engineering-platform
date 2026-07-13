"""Construction helper for the IR manager."""

from __future__ import annotations

from .config import IRConfig, load_ir_config
from .manager import IRManager

__all__ = ["build_ir_manager"]


def build_ir_manager(config: IRConfig | None = None) -> IRManager:
    """Construct an ``IRManager`` with resolved configuration."""

    return IRManager(config=config or load_ir_config())
