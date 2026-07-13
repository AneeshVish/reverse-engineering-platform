"""Protocol definitions later packages implement.

These describe how future packages (e.g. reporting) provide and consume
investigation cases. They are protocols only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .case import InvestigationCase

__all__ = ["InvestigationProvider", "InvestigationConsumer"]


@runtime_checkable
class InvestigationProvider(Protocol):
    """Produces an ``InvestigationCase`` (implemented by later packages)."""

    def provide(self) -> InvestigationCase: ...


@runtime_checkable
class InvestigationConsumer(Protocol):
    """Consumes an ``InvestigationCase`` (implemented by later packages)."""

    def consume(self, case: InvestigationCase) -> None: ...
