"""reveng-static-analysis — the static analysis framework.

Owner: Implementation Specification 006 (Static Analysis). This is the platform's
first real reverse-engineering capability: it consumes ``Artifact``s, runs
deterministic analyzers, produces canonical IR, and emits Evidence. It performs no
disassembly, decompilation, CFG/call-graph recovery, malware detection, reasoning,
graph construction, persistence, or AI inference.

Framework-first: the analyzer/registry/planner/executor/pipeline machinery is real
and deterministic; ISA-specific parsing remains placeholders.

Everything re-exported here constitutes the frozen Phase 008 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .analyzers import (
    DEFAULT_PRIORITY,
    Analyzer,
    AnalyzerCapability,
    AnalyzerMetadata,
    AnalyzerPriority,
    AnalyzerState,
)
from .config import STATIC_DEFAULTS, StaticAnalysisConfig, load_static_config
from .contracts import (
    AnalysisCapability,
    AnalysisContext,
    AnalysisRequest,
    AnalysisResult,
    AnalysisScope,
    AnalysisStatus,
)
from .errors import (
    AnalysisError,
    ExtractionError,
    ParserError,
    RegistrationError,
    StaticError,
    ValidationError,
    guard,
    make_error,
)
from .evidence import EvidenceBuilder
from .executor import AnalysisExecutor
from .extraction import (
    ExtractedExport,
    ExtractedHeader,
    ExtractedImport,
    ExtractedRelocation,
    ExtractedResource,
    ExtractedSection,
    ExtractedSegment,
    ExtractedString,
    ExtractedSymbol,
    ExtractionResult,
)
from .functions import FunctionBoundary, FunctionCandidate, FunctionMetadata
from .init import build_static_analysis
from .instructions import Architecture, InstructionModel
from .ir_builder import IRArtifactBuilder, IRBuildResult
from .manager import StaticAnalysisManager
from .pipeline import AnalysisPipeline, AnalysisReport
from .planner import AnalysisPlan, AnalysisPlanner
from .references import CrossReference, ReferenceKind, ReferenceTarget
from .reference import REFERENCE_ANALYZER_TYPES, register_builtin_analyzers
from .registry import AnalyzerRegistry

__version__ = "0.1.0"

__all__ = [
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
]
