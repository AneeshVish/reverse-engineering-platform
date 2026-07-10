"""Synchronous, deterministic pass scheduler.

Executes an :class:`ExecutionPlan` in order on the calling thread. There are no
worker pools, no async, and no parallelism (those belong to later phases).

Failure propagation: a pass whose declared dependency has failed or been skipped
is recorded ``SKIPPED`` (its dependency did not complete); independent passes
still run. Because the plan is topologically ordered, checking a pass's immediate
dependencies against the failed/skipped set propagates transitively.

Cancellation is cooperative: the scheduler checks a :class:`CancellationToken`
before each pass. Once cancelled, the current and all remaining passes are
recorded ``CANCELLED``.
"""

from __future__ import annotations

import threading

from .context import PassContext
from .errors import make_error
from .executor import Executor
from .planner import ExecutionPlan
from .registry import PassRegistry
from .results import ExecutionReport, PassResult, PassStatus

__all__ = ["CancellationToken", "Scheduler"]


class CancellationToken:
    """A cooperative, thread-safe cancellation flag."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled


class Scheduler:
    """Runs an execution plan synchronously and deterministically."""

    def __init__(self, executor: Executor | None = None) -> None:
        self._executor = executor or Executor()

    def run(
        self,
        plan: ExecutionPlan,
        registry: PassRegistry,
        context: PassContext,
        token: CancellationToken | None = None,
    ) -> ExecutionReport:
        results: list[PassResult] = []
        blocked: set[str] = set()
        cancelled = False

        for pass_id in plan.ordered_ids:
            if token is not None and token.cancelled:
                cancelled = True

            if cancelled:
                results.append(PassResult(pass_id=pass_id, status=PassStatus.CANCELLED))
                continue

            pass_ = registry.get(pass_id)
            failed_deps = [d for d in pass_.metadata.dependencies if d in blocked]
            if failed_deps:
                blocked.add(pass_id)
                results.append(
                    PassResult(
                        pass_id=pass_id,
                        status=PassStatus.SKIPPED,
                        error=make_error(
                            "PASS.DEPENDENCY",
                            "dependency did not complete",
                            pass_id=pass_id,
                            dependencies=tuple(failed_deps),
                        ),
                    )
                )
                continue

            result = self._executor.execute(pass_, context)
            if result.status is PassStatus.FAILED:
                blocked.add(pass_id)
            results.append(result)

        return ExecutionReport(results=tuple(results))
