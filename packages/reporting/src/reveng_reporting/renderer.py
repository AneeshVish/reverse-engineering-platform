"""Deterministic report renderers.

Render a ``Report`` to JSON, Markdown, or HTML. Output is byte-identical for
identical reports — sections are emitted in order, references are sorted, and no
timestamps or randomness appear. There is no PDF engine (that belongs to a later
phase).
"""

from __future__ import annotations

import html
import json
from enum import Enum

from .report import Report

__all__ = ["RenderFormat", "ReportRenderer"]


class RenderFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


class ReportRenderer:
    """Renders a report deterministically to a text format."""

    def render(self, report: Report, fmt: RenderFormat) -> str:
        if fmt is RenderFormat.JSON:
            return self._json(report)
        if fmt is RenderFormat.MARKDOWN:
            return self._markdown(report)
        return self._html(report)

    def _json(self, report: Report) -> str:
        payload = {
            "id": report.id.value,
            "case_id": report.case_id,
            "template": report.template,
            "title": report.title,
            "summary": report.summary,
            "state": report.state.value,
            "version": report.version,
            "sections": [
                {
                    "kind": s.kind.value,
                    "title": s.title,
                    "content": s.content,
                    "references": sorted(s.references),
                }
                for s in report.sections
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _markdown(self, report: Report) -> str:
        lines = [f"# {report.title}", "", report.summary, ""]
        for section in report.sections:
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            if section.references:
                lines.append("")
                lines.append("References: " + ", ".join(sorted(section.references)))
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _html(self, report: Report) -> str:
        parts = [
            "<article>",
            f"<h1>{html.escape(report.title)}</h1>",
            f"<p>{html.escape(report.summary)}</p>",
        ]
        for section in report.sections:
            parts.append(f"<section><h2>{html.escape(section.title)}</h2>")
            parts.append(f"<pre>{html.escape(section.content)}</pre>")
            if section.references:
                refs = ", ".join(html.escape(r) for r in sorted(section.references))
                parts.append(f"<p class=\"refs\">References: {refs}</p>")
            parts.append("</section>")
        parts.append("</article>")
        return "".join(parts)
