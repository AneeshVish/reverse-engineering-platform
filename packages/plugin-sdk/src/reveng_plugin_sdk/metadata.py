"""Immutable plugin metadata.

``PluginMetadata`` is a frozen self-description a plugin exposes. It carries no
behavior — the manager reads it to discover, order, and register the plugin.
"""

from __future__ import annotations

from dataclasses import dataclass

from .capabilities import CapabilityDescriptor

__all__ = ["PluginMetadata", "DEFAULT_PRIORITY"]

DEFAULT_PRIORITY = 100


@dataclass(frozen=True)
class PluginMetadata:
    """A plugin's immutable self-description."""

    identifier: str
    name: str = ""
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    capabilities: tuple[CapabilityDescriptor, ...] = ()
    dependencies: tuple[str, ...] = ()
    priority: int = DEFAULT_PRIORITY

    def capability_names(self) -> tuple[str, ...]:
        return tuple(sorted(c.name for c in self.capabilities))

    def extension_points(self) -> tuple[str, ...]:
        return tuple(sorted({c.extension_point.value for c in self.capabilities}))
