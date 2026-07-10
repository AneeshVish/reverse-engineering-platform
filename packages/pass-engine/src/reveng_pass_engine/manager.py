"""Pass engine manager.

Owns the pass registry and drives planning/execution through the pipeline. It
participates in the substrate lifecycle via the ``Component`` shape so a host
``Application`` can bring it up and shut it down. It holds no execution state
between runs.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState

from .config import PassEngineConfig
from .contracts import ExecutionRequest
from .passes import Pass
from .pipeline import Pipeline
from .planner import ExecutionPlan
from .registry import PassRegistry
from .results import ExecutionReport
from .scheduler import CancellationToken

__all__ = ["PassEngineManager"]


class PassEngineManager:
    """Lifecycle-aware coordinator over a pass registry and pipeline."""

    component_name = "pass-engine.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        registry: PassRegistry | None = None,
        pipeline: Pipeline | None = None,
        config: PassEngineConfig | None = None,
    ) -> None:
        self._registry = registry or PassRegistry()
        self._pipeline = pipeline or Pipeline()
        self._config = config or PassEngineConfig()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """No built-in passes to register; ready immediately."""

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- registration & execution -------------------------------------------

    @property
    def registry(self) -> PassRegistry:
        return self._registry

    def register(self, pass_: Pass) -> None:
        self._registry.register(pass_)

    def plan(self, request: ExecutionRequest) -> ExecutionPlan:
        return self._pipeline.plan(self._registry, request)

    def execute(
        self,
        request: ExecutionRequest,
        *,
        token: CancellationToken | None = None,
    ) -> ExecutionReport:
        return self._pipeline.execute(self._registry, request, token=token)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail=f"{len(self._registry)} passes")

    def health_state(self) -> HealthState:
        return self.health().state
