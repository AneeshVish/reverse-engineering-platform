"""The plugin abstraction.

A ``Plugin`` is a passive extension. It exposes immutable metadata and capabilities
and participates in a simple lifecycle; it contains no execution logic and never
invokes platform managers — managers invoke plugins. The ``ExecutionContext`` a
plugin receives is read-only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from reveng_core_substrate import HealthResult, HealthState

from .metadata import PluginMetadata

__all__ = ["Plugin"]


class Plugin(ABC):
    """Abstract passive plugin."""

    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return this plugin's immutable self-description."""

    @property
    def identifier(self) -> str:
        return self.metadata().identifier

    def initialize(self) -> None:
        """Prepare the plugin. Default: no-op (plugins hold no state)."""

    def shutdown(self) -> None:
        """Release the plugin. Default: no-op."""

    def health(self) -> HealthResult:
        """Report plugin health. Default: healthy."""

        return HealthResult(HealthState.HEALTHY)
