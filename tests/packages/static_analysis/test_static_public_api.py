"""Invariant: the Phase 008 public API is frozen.

Everything exported from ``reveng_static_analysis.__init__`` is the public API
established by Engineering Phase 008. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_static_analysis as static

PHASE_008_PUBLIC_API = frozenset(
    {
        "__version__",
        # analyzers
        "Analyzer",
        "AnalyzerMetadata",
        "AnalyzerCapability",
        "AnalyzerPriority",
        "AnalyzerState",
        "DEFAULT_PRIORITY",
        # contracts
        "AnalysisScope",
        "AnalysisCapability",
        "AnalysisStatus",
        "AnalysisRequest",
        "AnalysisContext",
        "AnalysisResult",
        # extraction
        "ExtractedHeader",
        "ExtractedSection",
        "ExtractedSegment",
        "ExtractedSymbol",
        "ExtractedString",
        "ExtractedImport",
        "ExtractedExport",
        "ExtractedRelocation",
        "ExtractedResource",
        "ExtractionResult",
        # framework primitives
        "Architecture",
        "InstructionModel",
        "ReferenceKind",
        "ReferenceTarget",
        "CrossReference",
        "FunctionBoundary",
        "FunctionMetadata",
        "FunctionCandidate",
        # framework
        "AnalyzerRegistry",
        "AnalysisPlanner",
        "AnalysisPlan",
        "AnalysisExecutor",
        "IRArtifactBuilder",
        "IRBuildResult",
        "EvidenceBuilder",
        "AnalysisPipeline",
        "AnalysisReport",
        "StaticAnalysisManager",
        "build_static_analysis",
        "register_builtin_analyzers",
        "REFERENCE_ANALYZER_TYPES",
        # config
        "StaticAnalysisConfig",
        "load_static_config",
        "STATIC_DEFAULTS",
        # errors
        "StaticError",
        "RegistrationError",
        "AnalysisError",
        "ParserError",
        "ExtractionError",
        "ValidationError",
        "make_error",
        "guard",
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_008_PUBLIC_API - set(static.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(static.__all__) - PHASE_008_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_008_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in static.__all__:
        assert hasattr(static, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(static.__all__) == len(set(static.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in static.__all__ if inspect.ismodule(getattr(static, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
