"""Construction helper for the plugin manager."""

from __future__ import annotations

from .config import PluginConfig, load_plugin_config
from .manager import PluginManager

__all__ = ["build_plugin_manager"]


def build_plugin_manager(config: PluginConfig | None = None) -> PluginManager:
    """Construct a ``PluginManager`` with resolved configuration."""

    return PluginManager(config=config or load_plugin_config())
