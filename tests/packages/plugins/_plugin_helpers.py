"""Shared test doubles for the plugin-SDK suite."""

from __future__ import annotations

from reveng_plugin_sdk import (
    CapabilityDescriptor,
    CapabilityKind,
    ExtensionPoint,
    Plugin,
    PluginMetadata,
)


class MockPlugin(Plugin):
    """A minimal configurable plugin for tests."""

    def __init__(
        self,
        identifier: str,
        *,
        dependencies: tuple[str, ...] = (),
        capability_names: tuple[str, ...] = (),
        priority: int = 100,
    ) -> None:
        self._identifier = identifier
        self._dependencies = dependencies
        self._capabilities = tuple(
            CapabilityDescriptor(
                kind=CapabilityKind.GENERIC,
                extension_point=ExtensionPoint.GENERIC,
                name=name,
            )
            for name in capability_names
        )
        self._priority = priority

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            identifier=self._identifier,
            name=self._identifier.title(),
            capabilities=self._capabilities,
            dependencies=self._dependencies,
            priority=self._priority,
        )


def chain() -> tuple[MockPlugin, ...]:
    """A -> B -> C dependency chain (declared out of order)."""

    return (
        MockPlugin("c", dependencies=("b",)),
        MockPlugin("a"),
        MockPlugin("b", dependencies=("a",)),
    )
