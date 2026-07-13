"""Extraction framework.

Immutable records for the entities a static analyzer can extract, plus the
``Extractor`` protocols that describe extractor shapes. These are framework
interfaces and data shapes only — no deep format parsing lives here. Reference
analyzers populate an ``ExtractionResult`` with metadata-level content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
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
    "HeaderExtractor",
    "SectionExtractor",
    "SymbolExtractor",
    "StringExtractor",
    "ImportExtractor",
    "ExportExtractor",
]


@dataclass(frozen=True)
class ExtractedHeader:
    name: str
    value: str = ""


@dataclass(frozen=True)
class ExtractedSection:
    name: str
    size: int = 0
    permissions: str = ""


@dataclass(frozen=True)
class ExtractedSegment:
    name: str
    permissions: str = ""


@dataclass(frozen=True)
class ExtractedSymbol:
    name: str
    kind: str = "unknown"


@dataclass(frozen=True)
class ExtractedString:
    value: str
    offset: int = 0
    encoding: str = "ascii"


@dataclass(frozen=True)
class ExtractedImport:
    name: str
    module: str = ""


@dataclass(frozen=True)
class ExtractedExport:
    name: str


@dataclass(frozen=True)
class ExtractedRelocation:
    offset: int
    kind: str = "unknown"


@dataclass(frozen=True)
class ExtractedResource:
    name: str
    kind: str = "unknown"


@dataclass(frozen=True)
class ExtractionResult:
    """The aggregate of everything one or more analyzers extracted."""

    headers: tuple[ExtractedHeader, ...] = field(default_factory=tuple)
    sections: tuple[ExtractedSection, ...] = field(default_factory=tuple)
    segments: tuple[ExtractedSegment, ...] = field(default_factory=tuple)
    symbols: tuple[ExtractedSymbol, ...] = field(default_factory=tuple)
    strings: tuple[ExtractedString, ...] = field(default_factory=tuple)
    imports: tuple[ExtractedImport, ...] = field(default_factory=tuple)
    exports: tuple[ExtractedExport, ...] = field(default_factory=tuple)
    relocations: tuple[ExtractedRelocation, ...] = field(default_factory=tuple)
    resources: tuple[ExtractedResource, ...] = field(default_factory=tuple)

    def merge(self, other: ExtractionResult) -> ExtractionResult:
        """Combine two results (used to aggregate per-analyzer extraction)."""

        return ExtractionResult(
            headers=self.headers + other.headers,
            sections=self.sections + other.sections,
            segments=self.segments + other.segments,
            symbols=self.symbols + other.symbols,
            strings=self.strings + other.strings,
            imports=self.imports + other.imports,
            exports=self.exports + other.exports,
            relocations=self.relocations + other.relocations,
            resources=self.resources + other.resources,
        )

    def is_empty(self) -> bool:
        return not any(
            (
                self.headers,
                self.sections,
                self.segments,
                self.symbols,
                self.strings,
                self.imports,
                self.exports,
                self.relocations,
                self.resources,
            )
        )


@runtime_checkable
class HeaderExtractor(Protocol):
    def extract_headers(self, content: bytes) -> tuple[ExtractedHeader, ...]: ...


@runtime_checkable
class SectionExtractor(Protocol):
    def extract_sections(self, content: bytes) -> tuple[ExtractedSection, ...]: ...


@runtime_checkable
class SymbolExtractor(Protocol):
    def extract_symbols(self, content: bytes) -> tuple[ExtractedSymbol, ...]: ...


@runtime_checkable
class StringExtractor(Protocol):
    def extract_strings(self, content: bytes) -> tuple[ExtractedString, ...]: ...


@runtime_checkable
class ImportExtractor(Protocol):
    def extract_imports(self, content: bytes) -> tuple[ExtractedImport, ...]: ...


@runtime_checkable
class ExportExtractor(Protocol):
    def extract_exports(self, content: bytes) -> tuple[ExtractedExport, ...]: ...
