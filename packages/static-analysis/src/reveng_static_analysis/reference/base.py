"""Base scaffolding for reference analyzers.

``ReferenceAnalyzer`` implements the ``Analyzer`` contract in a pure,
deterministic way. Concrete reference analyzers set a few class attributes and
override ``extract``. They perform no disassembly and no deep format parsing.
"""

from __future__ import annotations

from ..analyzers import DEFAULT_PRIORITY, Analyzer, AnalyzerCapability, AnalyzerMetadata
from ..contracts import AnalysisContext, AnalysisResult, AnalysisStatus
from ..extraction import ExtractionResult

__all__ = ["ReferenceAnalyzer"]


class ReferenceAnalyzer(Analyzer):
    """Common, deterministic base for reference analyzers."""

    identifier_: str = ""
    version_: str = "1.0.0"
    capabilities_: tuple[AnalyzerCapability, ...] = ()
    priority_: int = DEFAULT_PRIORITY

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            identifier=self.identifier_,
            version=self.version_,
            capabilities=self.capabilities_,
            applicable_types=(),  # framework applies to every artifact type
            priority=self.priority_,
        )

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        return AnalysisResult(
            analyzer_id=self.identifier_,
            status=AnalysisStatus.COMPLETED,
            extraction=self.extract(context),
        )

    def extract(self, context: AnalysisContext) -> ExtractionResult:
        """Return extracted entities. Placeholder default: nothing extracted."""

        return ExtractionResult()
