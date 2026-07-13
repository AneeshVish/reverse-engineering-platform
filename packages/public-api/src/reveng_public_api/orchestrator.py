"""The pipeline orchestrator.

Chains the nine backend managers exactly as their own APIs require: produce an
``Artifact`` from raw bytes, run static analysis (which persists evidence into
the given ``StorageManager`` internally), build the knowledge graph, derive
reasoning inferences, assemble an investigation case, build and render a
report. No analysis logic lives here -- every step delegates to the owning
backend manager; this module only threads their inputs/outputs together.

Determinism note: given the same input bytes and the same (already
deterministic) backend managers, ``PipelineOrchestrator.run`` produces a
bit-identical ``PipelineResult`` every time. The only non-determinism in this
package lives one layer up, in job/session identity (see ``identifiers.py``)
-- this module introduces none of its own.
"""

from __future__ import annotations

from dataclasses import dataclass

from reveng_domain_producers import Artifact, ProducerManager, ProducerRequest
from reveng_intermediate_representation import IRModule
from reveng_investigation import InvestigationManager
from reveng_knowledge_graph import KnowledgeGraphManager
from reveng_reasoning import ReasoningManager
from reveng_reporting import Report, RenderFormat, ReportingManager
from reveng_static_analysis import AnalysisRequest, StaticAnalysisManager
from reveng_storage_evidence import StorageManager

__all__ = ["PipelineResult", "PipelineOrchestrator"]


@dataclass(frozen=True)
class PipelineResult:
    """The immutable outcome of running the full pipeline over one artifact."""

    artifact_ref: str
    module: IRModule
    report: Report
    rendered: str


class PipelineOrchestrator:
    """Coordinates the nine backend managers into one end-to-end pipeline run."""

    def __init__(
        self,
        *,
        producers: ProducerManager,
        static_analysis: StaticAnalysisManager,
        storage: StorageManager,
        knowledge_graph: KnowledgeGraphManager,
        reasoning: ReasoningManager,
        investigation: InvestigationManager,
        reporting: ReportingManager,
    ) -> None:
        self._producers = producers
        self._static_analysis = static_analysis
        self._storage = storage
        self._knowledge_graph = knowledge_graph
        self._reasoning = reasoning
        self._investigation = investigation
        self._reporting = reporting

    def produce_artifact(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
    ) -> Artifact:
        request = ProducerRequest(
            content=content, source_ref=source_ref, hint_extension=hint_extension
        )
        return self._producers.produce(request)

    def run(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> PipelineResult:
        artifact = self.produce_artifact(
            content, source_ref=source_ref, hint_extension=hint_extension
        )
        analysis_request = AnalysisRequest(artifact=artifact, raw_content=content)
        analysis_report = self._static_analysis.analyze(analysis_request, storage=self._storage)

        graph = self._knowledge_graph.build(
            ir_module=analysis_report.module, evidence=analysis_report.evidence
        )
        reasoning_result = self._reasoning.run(graph, self._storage.repository)
        case = self._investigation.build(graph, self._storage.repository, reasoning_result)
        report = self._reporting.build(
            case,
            reasoning_result,
            self._storage.repository,
            graph,
            template_name=template_name,
        )
        rendered = self._reporting.render(report, RenderFormat.JSON)

        return PipelineResult(
            artifact_ref=analysis_report.artifact_ref,
            module=analysis_report.module,
            report=report,
            rendered=rendered,
        )
