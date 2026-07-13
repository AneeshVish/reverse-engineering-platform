"""Deterministic finding timeline.

Timelines order findings without any wall-clock time. Order is derived entirely
from the contributing ``InferenceID`` values (the sorted inference ids of each
finding, then the finding id as a tiebreak), so the same case always yields the
same timeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .case import InvestigationCase
from .finding import Finding

__all__ = ["Timeline", "build_timeline"]


def _order_key(finding: Finding) -> tuple[str, str]:
    first_inference = finding.explanation.inference_ids[0] if finding.explanation.inference_ids else ""
    return (first_inference, finding.id.value)


@dataclass(frozen=True)
class Timeline:
    """An immutable, deterministically-ordered sequence of findings."""

    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def ordered(self) -> tuple[Finding, ...]:
        return self.findings

    def __len__(self) -> int:
        return len(self.findings)


def build_timeline(case: InvestigationCase) -> Timeline:
    """Build a deterministic timeline from a case's findings."""

    return Timeline(tuple(sorted(case.findings, key=_order_key)))
