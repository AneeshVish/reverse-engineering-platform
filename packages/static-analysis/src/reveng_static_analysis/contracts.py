"""Static-analysis value contracts.

The request/context/result value types passed through the framework. These are
pure data; behavior lives in analyzers, the planner, and the executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from reveng_core_substrate import ExecutionContext
from reveng_domain_producers import Artifact

from .extraction import ExtractionResult

__all__ = [
    "AnalysisScope",
    "AnalysisCapability",
    "AnalysisRequest",
    "AnalysisContext",
    "AnalysisStatus",
    "AnalysisResult",
]


class AnalysisScope(str, Enum):
    """The granularity an analyzer operates at."""

    MODULE = "module"
    SECTION = "section"
    FUNCTION = "function"
    INSTRUCTION = "instruction"


class AnalysisCapability(str, Enum):
    """Capabilities an analysis can advertise (mirrors extraction categories)."""

    HEADERS = "headers"
    SECTIONS = "sections"
    SEGMENTS = "segments"
    SYMBOLS = "symbols"
    STRINGS = "strings"
    IMPORTS = "imports"
    EXPORTS = "exports"
    RELOCATIONS = "relocations"
    RESOURCES = "resources"
    ENTRYPOINT = "entrypoint"
    RAW_BYTES = "raw_bytes"


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class AnalysisRequest:
    """An analysis request: the artifact plus optional raw content.

    ``raw_content`` is optional because an ``Artifact`` is a descriptor, not the
    bytes. Analyzers that do not need content ignore it.
    """

    artifact: Artifact
    raw_content: bytes = b""
    options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisContext:
    """Immutable context handed to an analyzer's ``analyze``."""

    request: AnalysisRequest
    execution_context: ExecutionContext

    @property
    def artifact(self) -> Artifact:
        return self.request.artifact

    @property
    def raw_content(self) -> bytes:
        return self.request.raw_content

    @property
    def correlation_id(self) -> str:
        return self.execution_context.correlation_id


@dataclass(frozen=True)
class AnalysisResult:
    """The outcome of one analyzer: its extraction plus a status."""

    analyzer_id: str
    status: AnalysisStatus
    extraction: ExtractionResult = field(default_factory=ExtractionResult)
