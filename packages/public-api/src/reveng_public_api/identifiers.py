"""The package's one deliberate, scoped non-determinism exception.

Every backend package in this platform is content-deterministic: no
timestamps, UUIDs, or randomness. Job and session bookkeeping cannot follow
that rule — two byte-identical uploads submitted as separate jobs must still
get distinct job ids, and progress genuinely changes over wall-clock time.

This module isolates that exception behind two small, injectable seams
(``IdProvider`` and ``ClockProtocol``) so nothing else in the package calls
``uuid4()``/``datetime.now()`` directly, and so tests get fully predictable
ids/timings via dependency injection.
"""

from __future__ import annotations

import itertools
import threading
import time

__all__ = ["MonotonicIdProvider", "SystemClock", "FixedClock"]


class MonotonicIdProvider:
    """Mints deterministic, monotonically increasing ids from a counter.

    Not content-derived (two identical uploads must get different ids), but
    fully predictable given a fixed starting point: the same construction and
    call sequence always yields the same id sequence.
    """

    def __init__(self, *, start: int = 0) -> None:
        self._counter = itertools.count(start)
        self._lock = threading.Lock()

    def new_id(self, kind: str) -> str:
        with self._lock:
            n = next(self._counter)
        return f"{kind}-{n:012d}"


class SystemClock:
    """Production clock backed by ``time.monotonic()``."""

    def now(self) -> float:
        return time.monotonic()


class FixedClock:
    """Test clock: starts at a fixed value and only advances when told to."""

    def __init__(self, value: float = 0.0) -> None:
        self._value = value

    def now(self) -> float:
        return self._value

    def advance(self, seconds: float) -> None:
        self._value += seconds
