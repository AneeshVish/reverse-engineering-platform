"""Single-analyzer execution.

Runs one analyzer through the ``guard`` boundary so no raw exception escapes,
normalizing the outcome into an ``AnalysisResult`` stamped with the analyzer's
identifier. A raised exception becomes a ``FAILED`` result with empty extraction.
"""

from __future__ import annotations

from .analyzers import Analyzer
from .contracts import AnalysisContext, AnalysisResult, AnalysisStatus
from .errors import guard
from .extraction import ExtractionResult

__all__ = ["AnalysisExecutor"]


class AnalysisExecutor:
    """Executes a single analyzer and produces a normalized result."""

    def execute(self, analyzer: Analyzer, context: AnalysisContext) -> AnalysisResult:
        identifier = analyzer.metadata.identifier
        outcome = guard(lambda: analyzer.analyze(context))

        if outcome.ok:
            produced = outcome.value
            if isinstance(produced, AnalysisResult):
                # Re-stamp the engine's authoritative id.
                return AnalysisResult(
                    analyzer_id=identifier,
                    status=produced.status,
                    extraction=produced.extraction,
                )
            return AnalysisResult(
                analyzer_id=identifier,
                status=AnalysisStatus.FAILED,
                extraction=ExtractionResult(),
            )

        return AnalysisResult(
            analyzer_id=identifier,
            status=AnalysisStatus.FAILED,
            extraction=ExtractionResult(),
        )
