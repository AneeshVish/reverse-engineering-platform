"""Dependency-injection container and service discovery.

The container owns registration and resolution of infrastructure services. It
supports three registration shapes — eager instances, lazily-constructed
singletons, and per-resolution factories — and detects the three failure modes
that matter for a foundation layer: missing registrations, duplicate
registrations, and construction cycles.

Concurrency: mutation and resolution are guarded by a single re-entrant lock.
Singleton construction happens under the lock so a service is built at most
once even under concurrent first-resolution.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

from .errors import ContainerError

__all__ = ["Lifetime", "ServiceContainer"]

T = TypeVar("T")

# A factory receives the container so services may resolve their own dependencies.
Factory = Callable[["ServiceContainer"], Any]


class Lifetime(str, Enum):
    """How a registered service is instantiated across resolutions."""

    INSTANCE = "instance"
    SINGLETON = "singleton"
    FACTORY = "factory"


@dataclass
class _Registration:
    key: str
    lifetime: Lifetime
    factory: Factory | None
    instance: Any | None


class ServiceContainer:
    """Registry and resolver for infrastructure services.

    Keys are strings; callers typically use a stable service name. Resolution is
    by key, keeping the container free of any platform-specific type knowledge.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._registrations: dict[str, _Registration] = {}
        self._resolving: set[str] = set()

    def register_instance(self, key: str, instance: Any) -> None:
        """Register an already-constructed object under ``key``."""

        self._add(_Registration(key, Lifetime.INSTANCE, factory=None, instance=instance))

    def register_singleton(self, key: str, factory: Factory) -> None:
        """Register a factory whose single result is cached on first resolution."""

        self._add(_Registration(key, Lifetime.SINGLETON, factory=factory, instance=None))

    def register_factory(self, key: str, factory: Factory) -> None:
        """Register a factory invoked on every resolution."""

        self._add(_Registration(key, Lifetime.FACTORY, factory=factory, instance=None))

    def _add(self, registration: _Registration) -> None:
        with self._lock:
            if registration.key in self._registrations:
                raise ContainerError(
                    "service already registered",
                    key=registration.key,
                )
            self._registrations[registration.key] = registration

    def is_registered(self, key: str) -> bool:
        with self._lock:
            return key in self._registrations

    def keys(self) -> tuple[str, ...]:
        """Return registered keys in deterministic (sorted) order."""

        with self._lock:
            return tuple(sorted(self._registrations))

    def resolve(self, key: str) -> Any:
        """Resolve the service registered under ``key``.

        Raises ``ContainerError`` for a missing registration or when a
        construction cycle is detected.
        """

        with self._lock:
            registration = self._registrations.get(key)
            if registration is None:
                raise ContainerError("service not registered", key=key)

            if registration.lifetime is Lifetime.INSTANCE:
                return registration.instance

            if registration.lifetime is Lifetime.SINGLETON and registration.instance is not None:
                return registration.instance

            if key in self._resolving:
                raise ContainerError(
                    "construction cycle detected",
                    key=key,
                    chain=tuple(self._resolving),
                )

            assert registration.factory is not None  # guaranteed by registration shape
            self._resolving.add(key)
            try:
                built = registration.factory(self)
            finally:
                self._resolving.discard(key)

            if registration.lifetime is Lifetime.SINGLETON:
                registration.instance = built
            return built
