"""Protocol definitions later packages and third parties implement.

These describe how plugins are provided, consumed, and constructed. They are
protocols only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .plugin import Plugin

__all__ = ["PluginProvider", "PluginConsumer", "PluginFactory"]


@runtime_checkable
class PluginProvider(Protocol):
    """Supplies plugin instances to register."""

    def provide(self) -> tuple[Plugin, ...]: ...


@runtime_checkable
class PluginConsumer(Protocol):
    """Consumes a registered plugin (implemented by managers)."""

    def consume(self, plugin: Plugin) -> None: ...


@runtime_checkable
class PluginFactory(Protocol):
    """Constructs a plugin instance."""

    def create(self) -> Plugin: ...
