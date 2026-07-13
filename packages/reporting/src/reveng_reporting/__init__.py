"""reveng-reporting — the deterministic reporting subsystem.

Owner: Implementation Specification 008 (Reporting). This package consumes
immutable ``InvestigationCase`` objects (plus their referenced findings,
inferences, evidence, and graph entities) and produces deterministic, explainable
reports. It performs no analysis, reasoning, inference, investigation, graph
traversal, scoring, malware classification, AI, or persistence — it only
transforms already-derived information into structured reports. Every report
section references upstream ids only.

Everything re-exported here constitutes the frozen Phase 012 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .builders import ReportBuilder
from .config import REPORTING_DEFAULTS, ReportingConfig, load_reporting_config
from .contracts import ReportBuilderProtocol, ReportConsumer, ReportProvider
from .errors import (
    BuilderError,
    ReportingError,
    SerializationError,
    TemplateError,
    ValidationError,
    guard,
    make_error,
)
from .indexing import CaseIndex, FindingIndex, ReportIndex, SeverityIndex
from .init import build_reporting_manager
from .manager import ReportingManager
from .properties import PropertyBag, PropertyKey, PropertyValue
from .query import ReportQuery, ReportQueryFilter, ReportQueryResult
from .renderer import RenderFormat, ReportRenderer
from .report import Report, ReportID, ReportState
from .sections import ReportSection, SectionKind
from .serialization import ReportDeserializer, ReportSerializer
from .templates import (
    REFERENCE_TEMPLATE_TYPES,
    EvidenceTemplate,
    ExecutiveSummaryTemplate,
    JSONTemplate,
    MarkdownTemplate,
    RenderContext,
    TechnicalTemplate,
    Template,
)
from .validation import ReportValidator, validate_report

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # report model
    "ReportID",
    "ReportState",
    "Report",
    # sections
    "SectionKind",
    "ReportSection",
    # properties
    "PropertyKey",
    "PropertyValue",
    "PropertyBag",
    # templates
    "RenderContext",
    "Template",
    "ExecutiveSummaryTemplate",
    "TechnicalTemplate",
    "EvidenceTemplate",
    "JSONTemplate",
    "MarkdownTemplate",
    "REFERENCE_TEMPLATE_TYPES",
    # builder / renderer
    "ReportBuilder",
    "ReportRenderer",
    "RenderFormat",
    # validation
    "validate_report",
    "ReportValidator",
    # serialization
    "ReportSerializer",
    "ReportDeserializer",
    # indexing
    "ReportIndex",
    "CaseIndex",
    "FindingIndex",
    "SeverityIndex",
    # query
    "ReportQuery",
    "ReportQueryFilter",
    "ReportQueryResult",
    # contracts
    "ReportProvider",
    "ReportConsumer",
    "ReportBuilderProtocol",
    # config
    "ReportingConfig",
    "load_reporting_config",
    "REPORTING_DEFAULTS",
    # manager
    "ReportingManager",
    "build_reporting_manager",
    # errors
    "ReportingError",
    "BuilderError",
    "ValidationError",
    "SerializationError",
    "TemplateError",
    "make_error",
    "guard",
]
