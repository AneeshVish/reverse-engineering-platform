"""Producer registry.

The authoritative source of registered producers. Built on the substrate's
``KeyedRegistry`` for deterministic, registration-ordered enumeration. The set of
built-in producers is never treated as exhaustive — any producer registered here
(built-in or third-party) participates equally.
"""

from __future__ import annotations

from reveng_core_substrate import KeyedRegistry, RegistryError

from .contracts import Producer
from .errors import RegistrationError

__all__ = ["ProducerRegistry"]


class ProducerRegistry:
    """Keyed collection of producers, ordered by registration."""

    def __init__(self) -> None:
        self._registry: KeyedRegistry[Producer] = KeyedRegistry("producer")

    def register(self, producer: Producer) -> None:
        """Register ``producer`` under its ``name``.

        Raises ``RegistrationError`` on a missing name or a duplicate.
        """

        if not producer.name:
            raise RegistrationError("producer has no name")
        try:
            self._registry.register(producer.name, producer)
        except RegistryError as exc:
            raise RegistrationError("duplicate producer", name=producer.name) from exc

    def get(self, name: str) -> Producer:
        try:
            return self._registry.get(name)
        except RegistryError as exc:
            raise RegistrationError("producer not registered", name=name) from exc

    def contains(self, name: str) -> bool:
        return self._registry.contains(name)

    def names(self) -> tuple[str, ...]:
        """Producer names in registration order."""

        return self._registry.keys()

    def all(self) -> tuple[Producer, ...]:
        """All producers in registration order."""

        return tuple(value for _, value in self._registry.items())

    def __len__(self) -> int:
        return len(self._registry)
