"""Report section model.

A ``ReportSection`` is an immutable, deterministically-formatted block of a
report. Its ``references`` are identifiers only (finding, inference, evidence, or
graph ids) — the section never embeds copies of upstream objects, keeping the
report a pure projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["SectionKind", "ReportSection"]


class SectionKind(str, Enum):
    SUMMARY = "summary"
    FINDINGS = "findings"
    INFERENCES = "inferences"
    EVIDENCE = "evidence"
    GRAPH = "graph"
    APPENDIX = "appendix"


@dataclass(frozen=True)
class ReportSection:
    """An immutable report section referencing upstream ids only."""

    kind: SectionKind
    title: str
    content: str
    references: tuple[str, ...] = ()
