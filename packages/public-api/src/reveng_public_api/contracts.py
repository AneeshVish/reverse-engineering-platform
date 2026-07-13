"""Protocol definitions for the identity/time seams the job manager depends on.

These are the injection points that keep job/session bookkeeping testable
despite being the one deliberately non-deterministic corner of this package
(see ``identifiers.py``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["ClockProtocol", "IdProvider"]


@runtime_checkable
class ClockProtocol(Protocol):
    """A source of monotonic time, in seconds."""

    def now(self) -> float: ...


@runtime_checkable
class IdProvider(Protocol):
    """Mints unique identifiers for a given kind (e.g. ``"job"``)."""

    def new_id(self, kind: str) -> str: ...
