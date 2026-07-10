"""Pass execution results.

Result types the engine returns. The engine treats a pass's ``payload`` as an
opaque token: it is recorded and handed back unchanged, never inspected,
interpreted, or serialized here. What a payload *means* (symbols, CFGs, IR,
indicators, …) belongs entirely to later packages.

Determinism: results carry no timestamps, identifiers, or machine-specific values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from reveng_errors import EngError

__all__ = [
    "PassStatus",
    "FailureClass",
    "PassResult",
    "ExecutionReport",
]


class PassStatus(str, Enum):
    """Terminal status of a single pass execution."""

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class FailureClass(str, Enum):
    """Failure taxonomy from Implementation Specification 003 §11.

    Classification only; the engine does not act on it (no retries in this
    phase). Later phases may key recovery behavior off these classes.
    """

    NONE = "none"
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    RECOVERABLE = "recoverable"
    FATAL = "fatal"


@dataclass(frozen=True)
class PassResult:
    """Outcome of executing one pass.

    ``payload`` is deliberately typed ``object | None`` and is opaque to the
    engine — it is never inspected here.
    """

    pass_id: str
    status: PassStatus
    payload: object | None = None
    error: EngError | None = None
    failure_class: FailureClass = FailureClass.NONE

    @property
    def ok(self) -> bool:
        return self.status is PassStatus.COMPLETED


@dataclass(frozen=True)
class ExecutionReport:
    """Ordered results of an execution run plus a derived overall status."""

    results: tuple[PassResult, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return all(r.status in (PassStatus.COMPLETED, PassStatus.SKIPPED) for r in self.results)

    def by_id(self, pass_id: str) -> PassResult | None:
        for result in self.results:
            if result.pass_id == pass_id:
                return result
        return None

    def statuses(self) -> tuple[tuple[str, PassStatus], ...]:
        return tuple((r.pass_id, r.status) for r in self.results)
