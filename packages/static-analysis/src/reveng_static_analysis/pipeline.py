"""End-to-end static-analysis pipeline.

Orchestrates: artifact → analyzer selection → execution → aggregate extraction →
canonical IR → evidence → immutable ``AnalysisReport``. The pipeline holds no
durable state and persists nothing; evidence is optionally emitted into a caller-
supplied in-memory ``StorageManager``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reveng_core_substrate import ExecutionContext, new_context, use_context
from reveng_intermediate_representation import IRModule
from reveng_storage_evidence import Evidence, StorageManager

from .contracts import AnalysisContext, AnalysisRequest, AnalysisResult
from .evidence import EvidenceBuilder
from .executor import AnalysisExecutor
from .extraction import ExtractionResult
from .ir_builder import IRArtifactBuilder
from .planner import AnalysisPlan, AnalysisPlanner
from .registry import AnalyzerRegistry

__all__ = ["AnalysisReport", "AnalysisPipeline"]


@dataclass(frozen=True)
class AnalysisReport:
    """The immutable outcome of analyzing one artifact."""

    artifact_ref: str
    module: IRModule
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    results: tuple[AnalysisResult, ...] = field(default_factory=tuple)

    def statuses(self) -> tuple[tuple[str, str], ...]:
        return tuple((r.analyzer_id, r.status.value) for r in self.results)


class AnalysisPipeline:
    """Plans, executes, and assembles a static-analysis run."""

    def __init__(
        self,
        planner: AnalysisPlanner | None = None,
        executor: AnalysisExecutor | None = None,
    ) -> None:
        self._planner = planner or AnalysisPlanner()
        self._executor = executor or AnalysisExecutor()
        self._ir_builder = IRArtifactBuilder()
        self._evidence_builder = EvidenceBuilder()

    def plan(self, registry: AnalyzerRegistry, request: AnalysisRequest) -> AnalysisPlan:
        return self._planner.plan(registry, request)

    def analyze(
        self,
        registry: AnalyzerRegistry,
        request: AnalysisRequest,
        *,
        execution_context: ExecutionContext | None = None,
        storage: StorageManager | None = None,
    ) -> AnalysisReport:
        plan = self._planner.plan(registry, request)
        ctx = execution_context or new_context()
        analysis_ctx = AnalysisContext(request=request, execution_context=ctx)

        results: list[AnalysisResult] = []
        aggregate = ExtractionResult()
        with use_context(ctx):
            for analyzer_id in plan.ordered_ids:
                analyzer = registry.get(analyzer_id)
                result = self._executor.execute(analyzer, analysis_ctx)
                results.append(result)
                aggregate = aggregate.merge(result.extraction)

        ir_result = self._ir_builder.build(request.artifact, aggregate)
        evidence = self._evidence_builder.build(request.artifact, aggregate, ir_result)
        if storage is not None:
            self._evidence_builder.store(storage, evidence)

        return AnalysisReport(
            artifact_ref=request.artifact.identity.content_hash,
            module=ir_result.module,
            evidence=evidence,
            results=tuple(results),
        )
