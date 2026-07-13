"""Analyzer registry.

Authoritative collection of registered analyzers, keyed by identifier and
enumerated in registration order (deterministic). Built on the substrate's
``KeyedRegistry``.
"""

from __future__ import annotations

from reveng_core_substrate import KeyedRegistry, RegistryError

from .analyzers import Analyzer
from .errors import RegistrationError

__all__ = ["AnalyzerRegistry"]


class AnalyzerRegistry:
    """Keyed collection of analyzers in registration order."""

    def __init__(self) -> None:
        self._registry: KeyedRegistry[Analyzer] = KeyedRegistry("analyzer")

    def register(self, analyzer: Analyzer) -> None:
        identifier = analyzer.metadata.identifier
        if not identifier:
            raise RegistrationError("analyzer has no identifier")
        try:
            self._registry.register(identifier, analyzer)
        except RegistryError as exc:
            raise RegistrationError("duplicate analyzer", identifier=identifier) from exc

    def get(self, identifier: str) -> Analyzer:
        try:
            return self._registry.get(identifier)
        except RegistryError as exc:
            raise RegistrationError("analyzer not registered", identifier=identifier) from exc

    def contains(self, identifier: str) -> bool:
        return self._registry.contains(identifier)

    def identifiers(self) -> tuple[str, ...]:
        return self._registry.keys()

    def all(self) -> tuple[Analyzer, ...]:
        return tuple(value for _, value in self._registry.items())

    def __len__(self) -> int:
        return len(self._registry)
