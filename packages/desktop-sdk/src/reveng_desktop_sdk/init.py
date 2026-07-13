"""Construction helper for the desktop manager."""

from __future__ import annotations

from .config import DesktopSdkConfig
from .manager import DesktopManager

__all__ = ["build_desktop_manager"]


def build_desktop_manager(config: DesktopSdkConfig | None = None) -> DesktopManager:
    """Construct a ``DesktopManager`` with resolved configuration."""

    return DesktopManager(config=config)
