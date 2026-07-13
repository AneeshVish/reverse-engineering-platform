"""Static-analysis tests: extraction contracts and reference analyzers."""

from __future__ import annotations

from _static_helpers import make_artifact
from reveng_core_substrate import new_context
from reveng_static_analysis import (
    AnalysisContext,
    AnalysisRequest,
    ExtractedHeader,
    ExtractedString,
    ExtractionResult,
)
from reveng_static_analysis.reference import (
    BinaryHeaderAnalyzer,
    RawBytesAnalyzer,
    SectionTableAnalyzer,
    StringsAnalyzer,
)


def _ctx(raw: bytes = b"") -> AnalysisContext:
    art = make_artifact()
    return AnalysisContext(
        request=AnalysisRequest(artifact=art, raw_content=raw),
        execution_context=new_context(),
    )


def test_extraction_merge() -> None:
    a = ExtractionResult(headers=(ExtractedHeader("a"),))
    b = ExtractionResult(strings=(ExtractedString("x"),))
    merged = a.merge(b)
    assert len(merged.headers) == 1
    assert len(merged.strings) == 1
    assert not merged.is_empty()


def test_empty_extraction() -> None:
    assert ExtractionResult().is_empty()


def test_binary_header_emits_type_and_size() -> None:
    result = BinaryHeaderAnalyzer().extract(_ctx())
    names = {h.name for h in result.headers}
    assert names == {"type", "size"}


def test_raw_bytes_emits_hash_and_length() -> None:
    result = RawBytesAnalyzer().extract(_ctx())
    names = {h.name for h in result.headers}
    assert names == {"content_hash", "byte_length"}


def test_placeholder_analyzer_extracts_nothing() -> None:
    assert SectionTableAnalyzer().extract(_ctx()).is_empty()


def test_strings_scan_finds_printable_runs() -> None:
    raw = b"\x00\x01Hello\x00World!!\xff"
    result = StringsAnalyzer(min_length=4).extract(_ctx(raw))
    values = [s.value for s in result.strings]
    assert "Hello" in values
    assert "World!!" in values


def test_strings_respect_min_length() -> None:
    raw = b"\x00abc\x00abcdef\x00"
    result = StringsAnalyzer(min_length=5).extract(_ctx(raw))
    values = [s.value for s in result.strings]
    assert "abcdef" in values
    assert "abc" not in values


def test_strings_deterministic_and_ordered() -> None:
    raw = b"zebra\x00\x00alpha\x00\x00"
    first = StringsAnalyzer(min_length=4).extract(_ctx(raw))
    second = StringsAnalyzer(min_length=4).extract(_ctx(raw))
    assert first == second
    offsets = [s.offset for s in first.strings]
    assert offsets == sorted(offsets)


def test_strings_no_content_no_strings() -> None:
    assert StringsAnalyzer().extract(_ctx(b"")).is_empty()
