"""Reference analyzers.

Deterministic, metadata-level reference analyzers demonstrating the framework.
Only ``strings`` reads raw content (a bounded, shallow printable-ASCII scan);
``binary_header``, ``entrypoint``, and ``raw_bytes`` emit descriptor facts; the
format-structural analyzers are honest placeholders that declare a capability and
extract nothing, since real PE/ELF parsing is deep parsing and out of scope.

The reference set is not exhaustive: the registry is authoritative and open to
third-party analyzers.
"""

from __future__ import annotations

from ..analyzers import AnalyzerCapability
from ..config import StaticAnalysisConfig
from ..contracts import AnalysisContext
from ..extraction import ExtractedHeader, ExtractedString, ExtractionResult
from ..registry import AnalyzerRegistry
from .base import ReferenceAnalyzer

__all__ = [
    "ReferenceAnalyzer",
    "BinaryHeaderAnalyzer",
    "SectionTableAnalyzer",
    "SegmentTableAnalyzer",
    "ImportsAnalyzer",
    "ExportsAnalyzer",
    "SymbolsAnalyzer",
    "StringsAnalyzer",
    "ResourcesAnalyzer",
    "RelocationsAnalyzer",
    "EntrypointAnalyzer",
    "RawBytesAnalyzer",
    "REFERENCE_ANALYZER_TYPES",
    "register_builtin_analyzers",
]

_PRINTABLE = frozenset(range(0x20, 0x7F))


class BinaryHeaderAnalyzer(ReferenceAnalyzer):
    identifier_ = "binary_header"
    capabilities_ = (AnalyzerCapability.HEADERS,)

    def extract(self, context: AnalysisContext) -> ExtractionResult:
        artifact = context.artifact
        return ExtractionResult(
            headers=(
                ExtractedHeader(name="type", value=artifact.artifact_type.value),
                ExtractedHeader(name="size", value=str(artifact.source.size)),
            )
        )


class SectionTableAnalyzer(ReferenceAnalyzer):
    identifier_ = "section_table"
    capabilities_ = (AnalyzerCapability.SECTIONS,)


class SegmentTableAnalyzer(ReferenceAnalyzer):
    identifier_ = "segment_table"
    capabilities_ = (AnalyzerCapability.SEGMENTS,)


class ImportsAnalyzer(ReferenceAnalyzer):
    identifier_ = "imports"
    capabilities_ = (AnalyzerCapability.IMPORTS,)


class ExportsAnalyzer(ReferenceAnalyzer):
    identifier_ = "exports"
    capabilities_ = (AnalyzerCapability.EXPORTS,)


class SymbolsAnalyzer(ReferenceAnalyzer):
    identifier_ = "symbols"
    capabilities_ = (AnalyzerCapability.SYMBOLS,)


class ResourcesAnalyzer(ReferenceAnalyzer):
    identifier_ = "resources"
    capabilities_ = (AnalyzerCapability.RESOURCES,)


class RelocationsAnalyzer(ReferenceAnalyzer):
    identifier_ = "relocations"
    capabilities_ = (AnalyzerCapability.RELOCATIONS,)


class EntrypointAnalyzer(ReferenceAnalyzer):
    identifier_ = "entrypoint"
    capabilities_ = (AnalyzerCapability.ENTRYPOINT,)

    def extract(self, context: AnalysisContext) -> ExtractionResult:
        # No real entrypoint recovery; record a deterministic placeholder header.
        return ExtractionResult(headers=(ExtractedHeader(name="entrypoint", value="unknown"),))


class RawBytesAnalyzer(ReferenceAnalyzer):
    identifier_ = "raw_bytes"
    capabilities_ = (AnalyzerCapability.RAW_BYTES,)

    def extract(self, context: AnalysisContext) -> ExtractionResult:
        artifact = context.artifact
        return ExtractionResult(
            headers=(
                ExtractedHeader(name="content_hash", value=artifact.identity.content_hash),
                ExtractedHeader(name="byte_length", value=str(artifact.source.size)),
            )
        )


class StringsAnalyzer(ReferenceAnalyzer):
    identifier_ = "strings"
    capabilities_ = (AnalyzerCapability.STRINGS,)

    def __init__(self, min_length: int = 4) -> None:
        self._min_length = max(1, min_length)

    def extract(self, context: AnalysisContext) -> ExtractionResult:
        content = context.raw_content
        if not content:
            return ExtractionResult()
        strings: list[ExtractedString] = []
        run: list[int] = []
        start = 0
        for offset, byte in enumerate(content):
            if byte in _PRINTABLE:
                if not run:
                    start = offset
                run.append(byte)
                continue
            if len(run) >= self._min_length:
                strings.append(ExtractedString(value=bytes(run).decode("ascii"), offset=start))
            run = []
        if len(run) >= self._min_length:
            strings.append(ExtractedString(value=bytes(run).decode("ascii"), offset=start))
        return ExtractionResult(strings=tuple(strings))


REFERENCE_ANALYZER_TYPES: tuple[type[ReferenceAnalyzer], ...] = (
    BinaryHeaderAnalyzer,
    SectionTableAnalyzer,
    SegmentTableAnalyzer,
    ImportsAnalyzer,
    ExportsAnalyzer,
    SymbolsAnalyzer,
    StringsAnalyzer,
    ResourcesAnalyzer,
    RelocationsAnalyzer,
    EntrypointAnalyzer,
    RawBytesAnalyzer,
)


def register_builtin_analyzers(
    registry: AnalyzerRegistry, config: StaticAnalysisConfig | None = None
) -> None:
    """Register the reference analyzers into ``registry``."""

    min_length = config.min_string_length() if config is not None else 4
    for cls in REFERENCE_ANALYZER_TYPES:
        analyzer = StringsAnalyzer(min_length) if cls is StringsAnalyzer else cls()
        registry.register(analyzer)
