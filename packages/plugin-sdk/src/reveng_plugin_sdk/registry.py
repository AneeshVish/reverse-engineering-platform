"""Plugin registry.

Authoritative collection of registered plugins, keyed by identifier and enumerated
in registration order (deterministic). Built on the substrate's ``KeyedRegistry``.
"""

from __future__ import annotations

from reveng_core_substrate import KeyedRegistry, RegistryError

from .errors import RegistrationError
from .plugin import Plugin

__all__ = ["PluginRegistry"]


class PluginRegistry:
    """Keyed collection of plugins in registration order."""

    def __init__(self) -> None:
        self._registry: KeyedRegistry[Plugin] = KeyedRegistry("plugin")

    def register(self, plugin: Plugin) -> None:
        identifier = plugin.metadata().identifier
        if not identifier:
            raise RegistrationError("plugin has no identifier")
        try:
            self._registry.register(identifier, plugin)
        except RegistryError as exc:
            raise RegistrationError("duplicate plugin", identifier=identifier) from exc

    def get(self, identifier: str) -> Plugin:
        try:
            return self._registry.get(identifier)
        except RegistryError as exc:
            raise RegistrationError("plugin not registered", identifier=identifier) from exc

    def contains(self, identifier: str) -> bool:
        return self._registry.contains(identifier)

    def identifiers(self) -> tuple[str, ...]:
        return self._registry.keys()

    def all(self) -> tuple[Plugin, ...]:
        return tuple(value for _, value in self._registry.items())

    def __len__(self) -> int:
        return len(self._registry)
