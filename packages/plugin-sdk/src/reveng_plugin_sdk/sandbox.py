"""Plugin execution context (API-boundary sandbox).

The ``PluginExecutionContext`` is the immutable, read-only environment a manager
hands a plugin: a frozen configuration and the set of capabilities the plugin is
permitted to use. It provides capability filtering only — there is no OS/process
isolation (that is out of scope); the "sandbox" is the API boundary itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .capabilities import CapabilityDescriptor, CapabilityKind
from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = ["PluginExecutionContext"]


@dataclass(frozen=True)
class PluginExecutionContext:
    """An immutable, read-only execution context for a plugin."""

    config: PropertyBag = EMPTY_PROPERTIES
    capabilities: tuple[CapabilityDescriptor, ...] = field(default_factory=tuple)

    def has_capability(self, name: str) -> bool:
        return any(c.name == name for c in self.capabilities)

    def capabilities_of_kind(self, kind: CapabilityKind) -> tuple[CapabilityDescriptor, ...]:
        return tuple(c for c in self.capabilities if c.kind is kind)

    def allows(self, capability: CapabilityDescriptor) -> bool:
        return capability in self.capabilities
