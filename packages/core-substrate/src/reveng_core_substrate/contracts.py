"""Substrate-owned shared runtime contracts.

These protocols define the stable vocabulary that later platform packages
implement. The substrate itself provides the machinery (container, registries,
lifecycle) that operates over objects satisfying these contracts.

Architecture invariant: infrastructure vocabulary only. No reverse-engineering,
storage, scheduling, graph, reasoning, investigation, reporting, or plugin
semantics appear here.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

__all__ = [
    "HealthState",
    "HealthReport",
    "Disposable",
    "Lifecycle",
    "Service",
    "Component",
    "HealthReporter",
]


class HealthState(str, Enum):
    """Coarse health classification for a component or the application."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class HealthReport(Protocol):
    """Read-only view of a component's health at a point in time."""

    @property
    def state(self) -> HealthState: ...

    @property
    def detail(self) -> str: ...


@runtime_checkable
class Disposable(Protocol):
    """An object that releases resources deterministically on shutdown."""

    def dispose(self) -> None: ...


@runtime_checkable
class Lifecycle(Protocol):
    """An object participating in ordered startup and shutdown."""

    def initialize(self) -> None: ...

    def shutdown(self) -> None: ...


@runtime_checkable
class Service(Protocol):
    """A resolvable unit of infrastructure behavior held by the container.

    Services are identified by their registration key; this protocol marks the
    intent rather than constraining shape, so plain objects may be registered.
    """

    @property
    def service_name(self) -> str: ...


@runtime_checkable
class Component(Protocol):
    """A named participant in the application lifecycle.

    Components may declare dependencies on other components by name; the
    lifecycle manager uses those declarations to order initialization.
    """

    @property
    def component_name(self) -> str: ...

    @property
    def depends_on(self) -> tuple[str, ...]: ...

    def initialize(self) -> None: ...

    def shutdown(self) -> None: ...


@runtime_checkable
class HealthReporter(Protocol):
    """A component able to report its own health on demand."""

    def check_health(self) -> HealthReport: ...
