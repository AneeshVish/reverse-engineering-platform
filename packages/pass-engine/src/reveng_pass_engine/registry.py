"""Pass registry.

Authoritative collection of registered passes, keyed by identifier and enumerated
in registration order (deterministic). Built on the substrate's ``KeyedRegistry``.
"""

from __future__ import annotations

from reveng_core_substrate import KeyedRegistry, RegistryError

from .errors import RegistrationError
from .passes import Pass

__all__ = ["PassRegistry"]


class PassRegistry:
    """Keyed collection of passes in registration order."""

    def __init__(self) -> None:
        self._registry: KeyedRegistry[Pass] = KeyedRegistry("pass")

    def register(self, pass_: Pass) -> None:
        """Register ``pass_`` under its identifier.

        Raises ``RegistrationError`` on a missing identifier or a duplicate.
        """

        identifier = pass_.metadata.identifier
        if not identifier:
            raise RegistrationError("pass has no identifier")
        try:
            self._registry.register(identifier, pass_)
        except RegistryError as exc:
            raise RegistrationError("duplicate pass", identifier=identifier) from exc

    def get(self, identifier: str) -> Pass:
        try:
            return self._registry.get(identifier)
        except RegistryError as exc:
            raise RegistrationError("pass not registered", identifier=identifier) from exc

    def contains(self, identifier: str) -> bool:
        return self._registry.contains(identifier)

    def identifiers(self) -> tuple[str, ...]:
        """Registered identifiers in registration order."""

        return self._registry.keys()

    def all(self) -> tuple[Pass, ...]:
        """All passes in registration order."""

        return tuple(value for _, value in self._registry.items())

    def __len__(self) -> int:
        return len(self._registry)
