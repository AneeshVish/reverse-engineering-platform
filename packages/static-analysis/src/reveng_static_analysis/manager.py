"""Static-analysis manager.

Owns the analyzer registry, planner, executor, and pipeline, and participates in
the substrate lifecycle via the ``Component`` shape. ``initialize`` registers the
reference analyzers. Performs no analysis of its own beyond orchestration.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState
from reveng_storage_evidence import StorageManager

from .analyzers import Analyzer
from .config import StaticAnalysisConfig
from .contracts import AnalysisRequest
from .pipeline import AnalysisPipeline, AnalysisReport
from .planner import AnalysisPlan
from .registry import AnalyzerRegistry

__all__ = ["StaticAnalysisManager"]


class StaticAnalysisManager:
    """Lifecycle-aware facade over the static-analysis framework."""

    component_name = "static-analysis.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        pipeline: AnalysisPipeline | None = None,
        config: StaticAnalysisConfig | None = None,
        *,
        auto_register_builtins: bool = True,
    ) -> None:
        self._registry = registry or AnalyzerRegistry()
        self._pipeline = pipeline or AnalysisPipeline()
        self._config = config or StaticAnalysisConfig()
        self._auto_register_builtins = auto_register_builtins

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Register the reference analyzers unless the registry is preloaded."""

        if self._auto_register_builtins and len(self._registry) == 0:
            from .reference import register_builtin_analyzers

            register_builtin_analyzers(self._registry, self._config)

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- registration & execution -------------------------------------------

    @property
    def registry(self) -> AnalyzerRegistry:
        return self._registry

    @property
    def config(self) -> StaticAnalysisConfig:
        return self._config

    def register(self, analyzer: Analyzer) -> None:
        self._registry.register(analyzer)

    def plan(self, request: AnalysisRequest) -> AnalysisPlan:
        return self._pipeline.plan(self._registry, request)

    def analyze(
        self, request: AnalysisRequest, *, storage: StorageManager | None = None
    ) -> AnalysisReport:
        return self._pipeline.analyze(self._registry, request, storage=storage)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail=f"{len(self._registry)} analyzers")

    def health_state(self) -> HealthState:
        return self.health().state
