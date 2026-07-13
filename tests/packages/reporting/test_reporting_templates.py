"""Reporting tests: templates and deterministic rendering formats."""

from __future__ import annotations

import pytest
from _reporting_helpers import build_pipeline
from reveng_reporting import (
    REFERENCE_TEMPLATE_TYPES,
    EvidenceTemplate,
    JSONTemplate,
    MarkdownTemplate,
    RenderContext,
    RenderFormat,
    ReportBuilder,
    ReportRenderer,
    TechnicalTemplate,
)


def _ctx():
    case, reasoning, repo, graph = build_pipeline()
    return RenderContext(case=case, reasoning=reasoning, evidence=repo, graph=graph)


def test_five_reference_templates() -> None:
    names = {cls().name for cls in REFERENCE_TEMPLATE_TYPES}
    assert names == {"executive_summary", "technical", "evidence", "json", "markdown"}


def test_template_render_is_deterministic() -> None:
    ctx = _ctx()
    a = TechnicalTemplate().render(ctx)
    b = TechnicalTemplate().render(ctx)
    assert [(s.kind, s.content, s.references) for s in a] == [
        (s.kind, s.content, s.references) for s in b
    ]


def test_evidence_template_sections() -> None:
    sections = EvidenceTemplate().render(_ctx())
    assert tuple(s.kind.value for s in sections) == ("findings", "evidence")


def test_markdown_template_content_is_markdown() -> None:
    sections = MarkdownTemplate().render(_ctx())
    findings = next(s for s in sections if s.kind.value == "findings")
    assert "- **" in findings.content


def test_json_template_sections() -> None:
    sections = JSONTemplate().render(_ctx())
    assert tuple(s.kind.value for s in sections) == ("summary", "findings")


@pytest.mark.parametrize("fmt", list(RenderFormat))
def test_render_is_byte_identical(fmt: RenderFormat) -> None:
    case, reasoning, repo, graph = build_pipeline()
    a = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    b = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    assert ReportRenderer().render(a, fmt) == ReportRenderer().render(b, fmt)


def test_render_formats_differ() -> None:
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    renderer = ReportRenderer()
    j = renderer.render(report, RenderFormat.JSON)
    m = renderer.render(report, RenderFormat.MARKDOWN)
    h = renderer.render(report, RenderFormat.HTML)
    assert j != m != h
    assert h.startswith("<article>")
    assert m.startswith("# Report")


def test_html_is_escaped() -> None:
    # HTML rendering escapes content; no raw angle brackets from titles leak.
    case, reasoning, repo, graph = build_pipeline()
    report = ReportBuilder().build(case, reasoning, repo, graph, TechnicalTemplate())
    html = ReportRenderer().render(report, RenderFormat.HTML)
    assert "<script>" not in html
