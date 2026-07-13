"""Invariant: the Phase 012 public API is frozen.

Everything exported from ``reveng_reporting.__init__`` is the public API
established by Engineering Phase 012. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_reporting as rp

PHASE_012_PUBLIC_API = frozenset(
    {
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
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_012_PUBLIC_API - set(rp.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(rp.__all__) - PHASE_012_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_012_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in rp.__all__:
        assert hasattr(rp, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(rp.__all__) == len(set(rp.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in rp.__all__ if inspect.ismodule(getattr(rp, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
