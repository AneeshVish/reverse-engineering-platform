"""Protocol definitions later packages implement.

These describe how future packages store, provide, and consume evidence. They are
protocols only — no behavior lives here.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .evidence import Evidence, EvidenceID

__all__ = ["EvidenceStore", "EvidenceProvider", "EvidenceConsumer"]


@runtime_checkable
class EvidenceStore(Protocol):
    """A store that holds and retrieves evidence records."""

    def add(self, evidence: Evidence) -> None: ...

    def lookup(self, evidence_id: EvidenceID) -> Evidence | None: ...

    def enumerate(self) -> tuple[Evidence, ...]: ...


@runtime_checkable
class EvidenceProvider(Protocol):
    """Produces evidence records (implemented by later analysis packages)."""

    def provide(self) -> tuple[Evidence, ...]: ...


@runtime_checkable
class EvidenceConsumer(Protocol):
    """Consumes evidence records (implemented by later packages)."""

    def consume(self, evidence: Evidence) -> None: ...
