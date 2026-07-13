"""Rule registry.

Authoritative collection of registered rules, keyed by identifier and enumerated
in registration order (deterministic). Built on the substrate's ``KeyedRegistry``.
"""

from __future__ import annotations

from reveng_core_substrate import KeyedRegistry, RegistryError

from .errors import RegistrationError
from .rules import Rule

__all__ = ["RuleRegistry"]


class RuleRegistry:
    """Keyed collection of rules in registration order."""

    def __init__(self) -> None:
        self._registry: KeyedRegistry[Rule] = KeyedRegistry("rule")

    def register(self, rule: Rule) -> None:
        identifier = rule.metadata.identifier
        if not identifier:
            raise RegistrationError("rule has no identifier")
        try:
            self._registry.register(identifier, rule)
        except RegistryError as exc:
            raise RegistrationError("duplicate rule", identifier=identifier) from exc

    def get(self, identifier: str) -> Rule:
        try:
            return self._registry.get(identifier)
        except RegistryError as exc:
            raise RegistrationError("rule not registered", identifier=identifier) from exc

    def contains(self, identifier: str) -> bool:
        return self._registry.contains(identifier)

    def identifiers(self) -> tuple[str, ...]:
        return self._registry.keys()

    def all(self) -> tuple[Rule, ...]:
        return tuple(value for _, value in self._registry.items())

    def __len__(self) -> int:
        return len(self._registry)
