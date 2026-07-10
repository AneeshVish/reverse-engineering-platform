"""Producer factory — the open registration path.

Any producer, built-in or third-party, enters the registry through the factory,
which validates the instance's contract before admitting it. Nothing here assumes
the built-in set is complete; the factory exists precisely so external code can
extend the platform on equal footing.
"""

from __future__ import annotations

from .contracts import Producer
from .errors import RegistrationError
from .registry import ProducerRegistry

__all__ = ["ProducerFactory"]


class ProducerFactory:
    """Validates and registers producers into a :class:`ProducerRegistry`."""

    def __init__(self, registry: ProducerRegistry) -> None:
        self._registry = registry

    def register(self, producer: Producer) -> None:
        """Validate and register a producer instance."""

        self._validate(producer)
        self._registry.register(producer)

    def register_all(self, producers: tuple[Producer, ...]) -> None:
        for producer in producers:
            self.register(producer)

    @staticmethod
    def _validate(producer: Producer) -> None:
        if not isinstance(producer, Producer):
            raise RegistrationError("object is not a Producer")
        if not producer.name:
            raise RegistrationError("producer has no name")
        if not producer.version:
            raise RegistrationError("producer has no version", name=producer.name)
