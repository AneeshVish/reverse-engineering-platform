"""Reporting manager.

Owns the report builder, renderer, validator, serializer, query engine, and a
template registry, and participates in the substrate lifecycle via the
``Component`` shape. It projects investigation cases into reports; it performs no
analysis.
"""

from __future__ import annotations

from collections.abc import Iterable

from reveng_core_substrate import HealthResult, HealthState, KeyedRegistry, RegistryError
from reveng_investigation import InvestigationCase
from reveng_knowledge_graph import KnowledgeGraph
from reveng_reasoning import ReasoningResult
from reveng_storage_evidence import EvidenceRepository

from .builders import ReportBuilder
from .config import ReportingConfig
from .errors import TemplateError
from .query import ReportQuery, ReportQueryResult
from .renderer import RenderFormat, ReportRenderer
from .report import Report
from .serialization import ReportDeserializer, ReportSerializer
from .templates import REFERENCE_TEMPLATE_TYPES, Template
from .validation import validate_report

__all__ = ["ReportingManager"]


class ReportingManager:
    """Lifecycle-aware facade over report construction, rendering, and access."""

    component_name = "reporting.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        config: ReportingConfig | None = None,
        *,
        auto_register_templates: bool = True,
    ) -> None:
        self._config = config or ReportingConfig()
        self._builder = ReportBuilder()
        self._renderer = ReportRenderer()
        self._serializer = ReportSerializer()
        self._deserializer = ReportDeserializer()
        self._templates: KeyedRegistry[Template] = KeyedRegistry("template")
        self._auto_register = auto_register_templates

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Register the reference templates unless preloaded."""

        if self._auto_register and len(self._templates) == 0:
            for cls in REFERENCE_TEMPLATE_TYPES:
                template = cls()
                self._templates.register(template.name, template)

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- templates -----------------------------------------------------------

    def template(self, name: str) -> Template:
        try:
            return self._templates.get(name)
        except RegistryError as exc:
            raise TemplateError("template not registered", template=name) from exc

    def template_names(self) -> tuple[str, ...]:
        return self._templates.keys()

    # -- construction / rendering / query / validation / serialization -------

    def build(
        self,
        case: InvestigationCase,
        reasoning: ReasoningResult,
        evidence: EvidenceRepository,
        graph: KnowledgeGraph,
        template_name: str | None = None,
    ) -> Report:
        name = template_name or self._config.default_template()
        return self._builder.build(case, reasoning, evidence, graph, self.template(name))

    def render(self, report: Report, fmt: RenderFormat) -> str:
        return self._renderer.render(report, fmt)

    def query(self, reports: Iterable[Report], query: ReportQuery) -> ReportQueryResult:
        return query.run(reports)

    def validate(
        self,
        report: Report,
        case: InvestigationCase,
        reasoning: ReasoningResult,
        evidence: EvidenceRepository,
        graph: KnowledgeGraph,
    ) -> None:
        validate_report(report, case, reasoning, evidence, graph)

    def serialize(self, report: Report) -> str:
        return self._serializer.serialize(report)

    def deserialize(self, data: str) -> Report:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail=f"{len(self._templates)} templates")

    def health_state(self) -> HealthState:
        return self.health().state
