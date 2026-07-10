"""End-to-end execution pipeline.

Ties the planner and scheduler together: given a registry and an execution
request, plan the applicable passes then execute them synchronously, returning an
:class:`ExecutionReport`. Holds no durable state of its own.
"""

from __future__ import annotations

from reveng_core_substrate import ExecutionContext, new_context, use_context

from .context import PassContext
from .contracts import ExecutionRequest
from .planner import ExecutionPlan, Planner
from .registry import PassRegistry
from .results import ExecutionReport
from .scheduler import CancellationToken, Scheduler

__all__ = ["Pipeline"]


class Pipeline:
    """Plans and runs passes over an execution request."""

    def __init__(self, planner: Planner | None = None, scheduler: Scheduler | None = None) -> None:
        self._planner = planner or Planner()
        self._scheduler = scheduler or Scheduler()

    def plan(self, registry: PassRegistry, request: ExecutionRequest) -> ExecutionPlan:
        return self._planner.plan(registry, request)

    def execute(
        self,
        registry: PassRegistry,
        request: ExecutionRequest,
        *,
        execution_context: ExecutionContext | None = None,
        token: CancellationToken | None = None,
    ) -> ExecutionReport:
        plan = self._planner.plan(registry, request)
        ctx = execution_context or new_context()
        pass_context = PassContext(request=request, execution_context=ctx)
        with use_context(ctx):
            return self._scheduler.run(plan, registry, pass_context, token=token)
