"""Plugin loader.

Loads a set of candidate plugins: discovers them deterministically, validates
their metadata, resolves dependency order, and registers them with the registry in
that order. It performs no dynamic code generation or import.
"""

from __future__ import annotations

from collections.abc import Iterable

from .discovery import PluginDiscovery
from .errors import LoadingError
from .plugin import Plugin
from .registry import PluginRegistry
from .validation import resolve_load_order, validate_plugin

__all__ = ["PluginLoader"]


class PluginLoader:
    """Validates and registers plugins in deterministic dependency order."""

    def __init__(self, discovery: PluginDiscovery | None = None) -> None:
        self._discovery = discovery or PluginDiscovery()

    def load(self, candidates: Iterable[Plugin], registry: PluginRegistry) -> tuple[str, ...]:
        """Validate, order, and register plugins; return the load order."""

        discovered = self._discovery.discover(candidates)
        for plugin in discovered:
            validate_plugin(plugin)

        order = resolve_load_order(discovered)
        by_id = {p.metadata().identifier: p for p in discovered}
        for identifier in order:
            try:
                registry.register(by_id[identifier])
            except Exception as exc:  # noqa: BLE001 - normalize to a loading failure
                raise LoadingError("failed to register plugin", plugin=identifier) from exc
        return order
