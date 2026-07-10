"""Pass execution context.

``PassContext`` carries the execution request and a substrate
:class:`ExecutionContext` (correlation id + scoped values) into a pass. It is
propagated through the substrate's ``use_context`` mechanism so a pass can read
the current context without it being threaded through every call.
"""

from __future__ import annotations

from dataclasses import dataclass

from reveng_core_substrate import ExecutionContext
from reveng_domain_producers import Artifact

from .contracts import ExecutionRequest

__all__ = ["PassContext"]


@dataclass(frozen=True)
class PassContext:
    """Immutable execution context handed to a pass's ``run``."""

    request: ExecutionRequest
    execution_context: ExecutionContext

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return self.request.artifacts

    @property
    def correlation_id(self) -> str:
        return self.execution_context.correlation_id
