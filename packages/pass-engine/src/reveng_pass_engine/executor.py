"""Single-pass execution.

Runs one pass through the ``guard`` boundary so no raw exception escapes, and
normalizes the outcome into a :class:`PassResult` stamped with the engine's
authoritative pass identifier. The pass's ``payload`` is passed through
untouched — the executor never inspects it.
"""

from __future__ import annotations

from .context import PassContext
from .errors import guard, make_error
from .passes import Pass
from .results import FailureClass, PassResult, PassStatus

__all__ = ["Executor"]


class Executor:
    """Executes a single pass and produces a normalized result."""

    def execute(self, pass_: Pass, context: PassContext) -> PassResult:
        identifier = pass_.metadata.identifier
        outcome = guard(lambda: pass_.run(context))

        if outcome.ok:
            produced = outcome.value
            if not isinstance(produced, PassResult):
                return PassResult(
                    pass_id=identifier,
                    status=PassStatus.FAILED,
                    error=make_error(
                        "PASS.EXECUTION",
                        "pass did not return a PassResult",
                        pass_id=identifier,
                    ),
                    failure_class=FailureClass.PERMANENT,
                )
            # Re-stamp the engine's authoritative id; payload passes through opaque.
            return PassResult(
                pass_id=identifier,
                status=produced.status,
                payload=produced.payload,
                error=produced.error,
                failure_class=produced.failure_class,
            )

        # A raised exception is a permanent failure of this pass in the sync engine.
        return PassResult(
            pass_id=identifier,
            status=PassStatus.FAILED,
            error=outcome.error,
            failure_class=FailureClass.PERMANENT,
        )
