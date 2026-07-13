"""Static-analysis tests: executor guard boundary."""

from __future__ import annotations

from _static_helpers import make_request
from reveng_core_substrate import new_context
from reveng_static_analysis import (
    AnalysisContext,
    AnalysisExecutor,
    AnalysisResult,
    AnalysisStatus,
)
from reveng_static_analysis.reference import BinaryHeaderAnalyzer, ReferenceAnalyzer


def _ctx() -> AnalysisContext:
    return AnalysisContext(request=make_request(), execution_context=new_context())


def test_successful_analyzer_completes() -> None:
    result = AnalysisExecutor().execute(BinaryHeaderAnalyzer(), _ctx())
    assert result.status is AnalysisStatus.COMPLETED
    assert result.analyzer_id == "binary_header"
    assert len(result.extraction.headers) == 2


def test_raising_analyzer_becomes_failed() -> None:
    class Boom(ReferenceAnalyzer):
        identifier_ = "boom"

        def extract(self, context):
            raise RuntimeError("kaboom")

    result = AnalysisExecutor().execute(Boom(), _ctx())
    assert result.status is AnalysisStatus.FAILED
    assert result.extraction.is_empty()


def test_no_raw_exception_escapes() -> None:
    class Boom(ReferenceAnalyzer):
        identifier_ = "boom"

        def extract(self, context):
            raise ValueError("bad")

    result = AnalysisExecutor().execute(Boom(), _ctx())
    assert isinstance(result, AnalysisResult)


def test_result_is_stamped_with_identifier() -> None:
    class Mislabel(ReferenceAnalyzer):
        identifier_ = "real_id"

        def analyze(self, context):
            return AnalysisResult(analyzer_id="wrong", status=AnalysisStatus.COMPLETED)

    result = AnalysisExecutor().execute(Mislabel(), _ctx())
    assert result.analyzer_id == "real_id"
