"""Substrate registries.

Four plugin-independent registries built on a common keyed store:

* ``ComponentRegistry`` — lifecycle participants, ordered for the application.
* ``CapabilityRegistry`` — named capabilities the platform advertises.
* ``FeatureRegistry`` — named features with an enabled flag.
* ``ExtensionRegistry`` — extension points, each holding an ordered list of
  contributions (this is the substrate mechanism the Plugin SDK later builds on;
  the substrate defines the registry, not any plugin loading).

All registries are lock-guarded and enumerate in deterministic order.
"""

from __future__ import annotations

import threading
from typing import Any, Generic, TypeVar

from .errors import RegistryError

__all__ = [
    "KeyedRegistry",
    "ComponentRegistry",
    "CapabilityRegistry",
    "FeatureRegistry",
    "ExtensionRegistry",
]

V = TypeVar("V")


class KeyedRegistry(Generic[V]):
    """A one-value-per-key registry with deterministic enumeration.

    Registration order is preserved for enumeration so that lifecycle sequencing
    over components is stable and reproducible.
    """

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._lock = threading.RLock()
        self._items: dict[str, V] = {}
        self._order: list[str] = []

    def register(self, key: str, value: V) -> None:
        with self._lock:
            if key in self._items:
                raise RegistryError(
                    "duplicate registration",
                    kind=self._kind,
                    key=key,
                )
            self._items[key] = value
            self._order.append(key)

    def get(self, key: str) -> V:
        with self._lock:
            if key not in self._items:
                raise RegistryError("not registered", kind=self._kind, key=key)
            return self._items[key]

    def contains(self, key: str) -> bool:
        with self._lock:
            return key in self._items

    def keys(self) -> tuple[str, ...]:
        """Return keys in registration order."""

        with self._lock:
            return tuple(self._order)

    def items(self) -> tuple[tuple[str, V], ...]:
        """Return (key, value) pairs in registration order."""

        with self._lock:
            return tuple((key, self._items[key]) for key in self._order)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class ComponentRegistry(KeyedRegistry[Any]):
    """Registry of lifecycle components keyed by component name."""

    def __init__(self) -> None:
        super().__init__("component")


class CapabilityRegistry(KeyedRegistry[Any]):
    """Registry of named platform capabilities."""

    def __init__(self) -> None:
        super().__init__("capability")


class FeatureRegistry:
    """Registry of named features and their enabled state."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._features: dict[str, bool] = {}
        self._order: list[str] = []

    def register(self, name: str, *, enabled: bool = False) -> None:
        with self._lock:
            if name in self._features:
                raise RegistryError("duplicate feature", key=name)
            self._features[name] = enabled
            self._order.append(name)

    def set_enabled(self, name: str, enabled: bool) -> None:
        with self._lock:
            if name not in self._features:
                raise RegistryError("feature not registered", key=name)
            self._features[name] = enabled

    def is_enabled(self, name: str) -> bool:
        with self._lock:
            if name not in self._features:
                raise RegistryError("feature not registered", key=name)
            return self._features[name]

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._order)


class ExtensionRegistry:
    """Registry of extension points, each holding ordered contributions.

    An extension point is addressed by name; contributions accumulate in
    registration order. This is the substrate primitive later packages (notably
    the Plugin SDK) use to expose extensibility — the substrate owns the
    mechanism, never the extensions themselves.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._points: dict[str, list[Any]] = {}

    def register_point(self, point: str) -> None:
        with self._lock:
            if point in self._points:
                raise RegistryError("duplicate extension point", key=point)
            self._points[point] = []

    def contribute(self, point: str, extension: Any) -> None:
        with self._lock:
            if point not in self._points:
                raise RegistryError("extension point not registered", key=point)
            self._points[point].append(extension)

    def extensions(self, point: str) -> tuple[Any, ...]:
        """Return contributions for ``point`` in registration order."""

        with self._lock:
            if point not in self._points:
                raise RegistryError("extension point not registered", key=point)
            return tuple(self._points[point])

    def points(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._points))
