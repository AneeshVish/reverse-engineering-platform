"""The report model.

A ``Report`` is an immutable projection of an investigation case into structured
sections. Its identity is ``SHA256(case_id | template | version)`` so the same
case and template always produce the same report id. Updates create new reports;
nothing is mutated in place.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .properties import EMPTY_PROPERTIES, PropertyBag
from .sections import ReportSection

__all__ = ["ReportID", "ReportState", "Report"]

_SEP = "|"


class ReportState(str, Enum):
    DRAFT = "draft"
    FINAL = "final"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class ReportID:
    """A content-derived report identity (hex SHA-256)."""

    value: str

    @classmethod
    def of(cls, case_id: str, template: str, version: int) -> ReportID:
        payload = _SEP.join((case_id, template, str(version)))
        return cls(hashlib.sha256(payload.encode("utf-8")).hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Report:
    """An immutable report projected from an investigation case."""

    id: ReportID
    case_id: str
    template: str
    title: str
    summary: str
    sections: tuple[ReportSection, ...] = field(default_factory=tuple)
    properties: PropertyBag = EMPTY_PROPERTIES
    state: ReportState = ReportState.DRAFT
    version: int = 1

    def section_kinds(self) -> tuple[str, ...]:
        return tuple(s.kind.value for s in self.sections)

    def references(self) -> tuple[str, ...]:
        refs: set[str] = set()
        for section in self.sections:
            refs.update(section.references)
        return tuple(sorted(refs))

    def __len__(self) -> int:
        return len(self.sections)
