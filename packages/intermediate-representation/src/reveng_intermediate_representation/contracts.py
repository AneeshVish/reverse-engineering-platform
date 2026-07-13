"""Protocol definitions later packages implement.

These protocols describe how future packages produce, consume, and transform IR.
They are intentionally decoupled from the ingestion layer: an ``IRProvider``
accepts an opaque ``source`` object, so the IR package never depends on the
domain-producers artifact model.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .nodes import IRModule

__all__ = ["IRProvider", "IRConsumer", "IRTransform"]


@runtime_checkable
class IRProvider(Protocol):
    """Produces an ``IRModule`` from some opaque source (implemented later)."""

    def provide(self, source: object) -> IRModule: ...


@runtime_checkable
class IRConsumer(Protocol):
    """Consumes an ``IRModule`` (implemented later)."""

    def consume(self, module: IRModule) -> None: ...


@runtime_checkable
class IRTransform(Protocol):
    """Transforms an ``IRModule`` into a new ``IRModule`` (never in place)."""

    def transform(self, module: IRModule) -> IRModule: ...
