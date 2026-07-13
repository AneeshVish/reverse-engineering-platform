"""Static-analysis tests: end-to-end pipeline, IR + evidence, determinism."""

from __future__ import annotations

from _static_helpers import make_artifact
from reveng_intermediate_representation import IRSerializer, NodeKind
from reveng_static_analysis import (
    AnalysisPipeline,
    AnalysisRequest,
    AnalyzerRegistry,
    register_builtin_analyzers,
)
from reveng_storage_evidence import build_storage_manager

_CONTENT = b"MZ\x90\x00Hello World, a printable string here!"


def _registry() -> AnalyzerRegistry:
    reg = AnalyzerRegistry()
    register_builtin_analyzers(reg)
    return reg


def _request() -> AnalysisRequest:
    art = make_artifact(content=_CONTENT)
    return AnalysisRequest(artifact=art, raw_content=_CONTENT)


def test_pipeline_produces_ir_module() -> None:
    report = AnalysisPipeline().analyze(_registry(), _request())
    assert len(report.module.nodes) >= 1
    assert report.module.nodes_of_kind(NodeKind.MODULE)


def test_pipeline_emits_evidence() -> None:
    report = AnalysisPipeline().analyze(_registry(), _request())
    assert len(report.evidence) > 0
    # An artifact anchor and an IR-module evidence are always present.
    kinds = {e.kind.value for e in report.evidence}
    assert "artifact" in kinds
    assert "ir_module" in kinds


def test_pipeline_extracts_strings() -> None:
    report = AnalysisPipeline().analyze(_registry(), _request())
    string_ev = [e for e in report.evidence if isinstance(e.payload, dict) and "value" in e.payload]
    assert any("Hello World" in e.payload["value"] for e in string_ev)  # type: ignore[index]


def test_all_analyzers_complete() -> None:
    report = AnalysisPipeline().analyze(_registry(), _request())
    assert all(status == "completed" for _, status in report.statuses())


def test_deterministic_repeated_execution() -> None:
    req = _request()
    a = AnalysisPipeline().analyze(_registry(), req)
    b = AnalysisPipeline().analyze(_registry(), req)
    assert IRSerializer().serialize(a.module) == IRSerializer().serialize(b.module)
    assert [e.id.value for e in a.evidence] == [e.id.value for e in b.evidence]


def test_evidence_ids_sorted() -> None:
    report = AnalysisPipeline().analyze(_registry(), _request())
    ids = [e.id.value for e in report.evidence]
    assert ids == sorted(ids)


def test_pipeline_emits_into_storage() -> None:
    store = build_storage_manager()
    report = AnalysisPipeline().analyze(_registry(), _request(), storage=store)
    assert len(store.enumerate()) == len(report.evidence)


def test_pipeline_does_not_mutate_artifact() -> None:
    req = _request()
    before = req.artifact.identity.content_hash
    AnalysisPipeline().analyze(_registry(), req)
    assert req.artifact.identity.content_hash == before
