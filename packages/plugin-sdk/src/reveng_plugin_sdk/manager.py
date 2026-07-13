"""Plugin manager.

Owns discovery, the loader, the registry, dependency resolution, and lifecycle,
and participates in the substrate lifecycle via the ``Component`` shape. It loads
and orders plugins deterministically and drives their lifecycle; plugins remain
passive and never invoke the manager.
"""

from __future__ import annotations

from collections.abc import Iterable

from reveng_core_substrate import HealthAggregator, HealthResult, HealthState

from .config import PluginConfig
from .dependency import resolve_load_order
from .discovery import PluginDiscovery
from .loader import PluginLoader
from .plugin import Plugin
from .registry import PluginRegistry
from .sandbox import PluginExecutionContext
from .validation import validate_plugins

__all__ = ["PluginManager"]


class PluginManager:
    """Lifecycle-aware coordinator over plugin discovery, loading, and access."""

    component_name = "plugin-sdk.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        config: PluginConfig | None = None,
        *,
        auto_load_reference: bool = True,
    ) -> None:
        self._config = config or PluginConfig()
        self._registry = PluginRegistry()
        self._discovery = PluginDiscovery()
        self._loader = PluginLoader(self._discovery)
        self._auto_load_reference = auto_load_reference
        self._load_order: tuple[str, ...] = ()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Load the reference plugins and initialize them in dependency order."""

        if self._auto_load_reference and len(self._registry) == 0:
            from .reference import reference_plugins

            self.load(reference_plugins())
        for plugin in self._ordered_plugins():
            plugin.initialize()

    def shutdown(self) -> None:
        """Shut down plugins in reverse load order (best-effort)."""

        for plugin in reversed(self._ordered_plugins()):
            try:
                plugin.shutdown()
            except Exception:  # noqa: BLE001 - best-effort shutdown
                pass

    # -- loading & access ----------------------------------------------------

    def load(self, candidates: Iterable[Plugin]) -> tuple[str, ...]:
        self._load_order = self._loader.load(candidates, self._registry)
        return self._load_order

    @property
    def registry(self) -> PluginRegistry:
        return self._registry

    def load_order(self) -> tuple[str, ...]:
        return self._load_order

    def discover(self, candidates: Iterable[Plugin]) -> tuple[Plugin, ...]:
        return self._discovery.discover(candidates)

    def resolve(self, plugins: Iterable[Plugin]) -> tuple[str, ...]:
        return resolve_load_order(tuple(plugins))

    def validate(self, plugins: Iterable[Plugin]) -> None:
        validate_plugins(tuple(plugins))

    def execution_context(self, plugin: Plugin) -> PluginExecutionContext:
        """Build the read-only execution context for a plugin from its metadata."""

        return PluginExecutionContext(capabilities=plugin.metadata().capabilities)

    def _ordered_plugins(self) -> tuple[Plugin, ...]:
        return tuple(self._registry.get(pid) for pid in self._load_order)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        aggregator = HealthAggregator()
        for plugin in self._registry.all():
            aggregator.register(plugin.identifier, plugin.health)
        overall = aggregator.evaluate().overall
        return HealthResult(overall, detail=f"{len(self._registry)} plugins")

    def health_state(self) -> HealthState:
        return self.health().state
