"""Execution context and request/context propagation.

An ``ExecutionContext`` carries a correlation id and a set of scoped values
across a unit of work. Propagation uses ``contextvars`` so that the current
context is isolated per-thread and per-async-task without any shared mutable
state, making it thread-safe by construction.
"""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from .errors import ContextError

__all__ = ["ExecutionContext", "current_context", "use_context", "new_context"]


@dataclass(frozen=True)
class ExecutionContext:
    """Immutable carrier of correlation identity and scoped values.

    Contexts are immutable; ``with_value`` returns a derived copy rather than
    mutating in place, which keeps propagation free of aliasing hazards.
    """

    correlation_id: str
    values: Mapping[str, Any] = field(default_factory=dict)

    def with_value(self, key: str, value: Any) -> ExecutionContext:
        merged = dict(self.values)
        merged[key] = value
        return replace(self, values=merged)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


_CURRENT: contextvars.ContextVar[ExecutionContext | None] = contextvars.ContextVar(
    "reveng_substrate_context", default=None
)


def new_context(correlation_id: str | None = None, **values: Any) -> ExecutionContext:
    """Create a fresh context, generating a correlation id when absent."""

    return ExecutionContext(
        correlation_id=correlation_id or uuid.uuid4().hex,
        values=dict(values),
    )


def current_context() -> ExecutionContext:
    """Return the active context, or raise if none is bound."""

    ctx = _CURRENT.get()
    if ctx is None:
        raise ContextError("no active execution context")
    return ctx


@contextmanager
def use_context(context: ExecutionContext) -> Iterator[ExecutionContext]:
    """Bind ``context`` as current for the duration of the ``with`` block.

    The previous context (if any) is restored on exit, so nesting is safe and
    balanced even when exceptions unwind the stack.
    """

    token = _CURRENT.set(context)
    try:
        yield context
    finally:
        _CURRENT.reset(token)
