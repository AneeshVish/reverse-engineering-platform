"""Protocol definitions later packages implement.

These describe how future packages provide reasoning results, consume them, and
supply rules. They are protocols only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .engine import ReasoningResult
from .rules import Rule

__all__ = ["ReasoningProvider", "ReasoningConsumer", "RuleProvider"]


@runtime_checkable
class ReasoningProvider(Protocol):
    """Produces a ``ReasoningResult`` (implemented by later packages)."""

    def provide(self) -> ReasoningResult: ...


@runtime_checkable
class ReasoningConsumer(Protocol):
    """Consumes a ``ReasoningResult`` (implemented by later packages)."""

    def consume(self, result: ReasoningResult) -> None: ...


@runtime_checkable
class RuleProvider(Protocol):
    """Supplies rules to register (implemented by later packages / plugins)."""

    def rules(self) -> tuple[Rule, ...]: ...
