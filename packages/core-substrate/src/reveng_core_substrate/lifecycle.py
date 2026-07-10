"""Application lifecycle framework.

``Application`` is the substrate entry object. It owns the container, the four
registries, the event dispatcher, and the health aggregator, and drives an
explicit lifecycle state machine:

    CREATED -> INITIALIZING -> READY -> SHUTTING_DOWN -> STOPPED

with a terminal FAILED state reachable from either transition. Components are
initialized in dependency order (a deterministic topological sort with
registration-order tiebreak) and shut down in the exact reverse order. Lifecycle
hooks fire around each phase. State transitions publish events on the dispatcher.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from enum import Enum

from .container import ServiceContainer
from .errors import LifecycleError
from .events import Event, EventDispatcher
from .health import HealthAggregator
from .registry import (
    CapabilityRegistry,
    ComponentRegistry,
    ExtensionRegistry,
    FeatureRegistry,
)

__all__ = ["LifecycleState", "LifecycleHook", "Application"]


class LifecycleState(str, Enum):
    """States of the application lifecycle."""

    CREATED = "created"
    INITIALIZING = "initializing"
    READY = "ready"
    SHUTTING_DOWN = "shutting_down"
    STOPPED = "stopped"
    FAILED = "failed"


LifecycleHook = Callable[["Application"], None]

# Lifecycle event topics published on the dispatcher.
EVENT_STATE_CHANGED = "substrate.lifecycle.state_changed"
EVENT_COMPONENT_INITIALIZED = "substrate.lifecycle.component_initialized"
EVENT_COMPONENT_SHUTDOWN = "substrate.lifecycle.component_shutdown"


def _topological_order(components: list[object]) -> list[str]:
    """Order component names so dependencies precede dependents.

    Deterministic: among nodes with no remaining unmet dependency, the one
    registered earliest is chosen first. Raises ``LifecycleError`` on a missing
    dependency or a cycle.
    """

    names = [getattr(c, "component_name") for c in components]
    index = {name: pos for pos, name in enumerate(names)}
    deps: dict[str, list[str]] = {}
    for comp in components:
        name = getattr(comp, "component_name")
        declared = tuple(getattr(comp, "depends_on", ()))
        for dep in declared:
            if dep not in index:
                raise LifecycleError(
                    "component depends on unregistered component",
                    component=name,
                    missing=dep,
                )
        deps[name] = list(declared)

    remaining = set(names)
    ordered: list[str] = []
    while remaining:
        ready = sorted(
            (n for n in remaining if all(d in ordered for d in deps[n])),
            key=lambda n: index[n],
        )
        if not ready:
            raise LifecycleError(
                "dependency cycle among components",
                unresolved=tuple(sorted(remaining, key=lambda n: index[n])),
            )
        for name in ready:
            ordered.append(name)
            remaining.discard(name)
    return ordered


class Application:
    """The substrate application object and lifecycle owner."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = LifecycleState.CREATED
        self.container = ServiceContainer()
        self.components = ComponentRegistry()
        self.capabilities = CapabilityRegistry()
        self.features = FeatureRegistry()
        self.extensions = ExtensionRegistry()
        self.events = EventDispatcher()
        self.health = HealthAggregator()
        self._init_order: list[str] = []
        self._pre_init: list[LifecycleHook] = []
        self._post_init: list[LifecycleHook] = []
        self._pre_shutdown: list[LifecycleHook] = []
        self._post_shutdown: list[LifecycleHook] = []

    @property
    def state(self) -> LifecycleState:
        with self._lock:
            return self._state

    def _set_state(self, state: LifecycleState) -> None:
        self._state = state
        self.events.publish(Event(EVENT_STATE_CHANGED, payload=state))

    def register_component(self, component: object) -> None:
        """Register a lifecycle component (must expose the ``Component`` shape)."""

        with self._lock:
            if self._state is not LifecycleState.CREATED:
                raise LifecycleError(
                    "components may only be registered before initialization",
                    state=self._state.value,
                )
            name = getattr(component, "component_name", None)
            if not isinstance(name, str) or not name:
                raise LifecycleError("component missing component_name")
            self.components.register(name, component)

    def on_pre_init(self, hook: LifecycleHook) -> None:
        self._pre_init.append(hook)

    def on_post_init(self, hook: LifecycleHook) -> None:
        self._post_init.append(hook)

    def on_pre_shutdown(self, hook: LifecycleHook) -> None:
        self._pre_shutdown.append(hook)

    def on_post_shutdown(self, hook: LifecycleHook) -> None:
        self._post_shutdown.append(hook)

    def initialize(self) -> None:
        """Initialize all components in dependency order.

        On any failure the application transitions to FAILED and the error is
        raised as a ``LifecycleError``; already-initialized components are left
        for an explicit ``shutdown`` call by the caller.
        """

        with self._lock:
            if self._state is not LifecycleState.CREATED:
                raise LifecycleError(
                    "initialize called from invalid state",
                    state=self._state.value,
                )
            self._set_state(LifecycleState.INITIALIZING)
            try:
                for hook in self._pre_init:
                    hook(self)
                components = [value for _, value in self.components.items()]
                order = _topological_order(components)
                for name in order:
                    component = self.components.get(name)
                    component.initialize()
                    self._init_order.append(name)
                    self.events.publish(Event(EVENT_COMPONENT_INITIALIZED, payload=name))
                for hook in self._post_init:
                    hook(self)
            except LifecycleError:
                self._set_state(LifecycleState.FAILED)
                raise
            except Exception as exc:  # noqa: BLE001 - convert to lifecycle failure
                self._set_state(LifecycleState.FAILED)
                raise LifecycleError("component initialization failed", cause=str(exc)) from exc
            self._set_state(LifecycleState.READY)

    def shutdown(self) -> None:
        """Shut down initialized components in reverse initialization order.

        Shutdown is best-effort: a failing component does not abort the sequence.
        The application always reaches STOPPED so resources are released.
        """

        with self._lock:
            if self._state not in (
                LifecycleState.READY,
                LifecycleState.FAILED,
                LifecycleState.INITIALIZING,
            ):
                raise LifecycleError(
                    "shutdown called from invalid state",
                    state=self._state.value,
                )
            self._set_state(LifecycleState.SHUTTING_DOWN)
            for hook in self._pre_shutdown:
                _safe_hook(hook, self)
            for name in reversed(self._init_order):
                component = self.components.get(name)
                try:
                    component.shutdown()
                except Exception:  # noqa: BLE001 - best-effort shutdown
                    pass
                else:
                    self.events.publish(Event(EVENT_COMPONENT_SHUTDOWN, payload=name))
            self._init_order.clear()
            for hook in self._post_shutdown:
                _safe_hook(hook, self)
            self._set_state(LifecycleState.STOPPED)


def _safe_hook(hook: LifecycleHook, app: Application) -> None:
    try:
        hook(app)
    except Exception:  # noqa: BLE001 - hooks must not break the sequence
        pass
