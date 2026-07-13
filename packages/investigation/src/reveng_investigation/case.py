"""The investigation case model.

An ``InvestigationCase`` is an immutable grouping of findings. Its identity is
``SHA256(sorted contributing inference ids)`` so the same inferences always
produce the same case id. Findings are stored in deterministic (id-sorted) order.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .finding import Finding
from .properties import EMPTY_PROPERTIES, PropertyBag

__all__ = ["CaseStatus", "CasePriority", "CaseID", "InvestigationCase"]


class CaseStatus(str, Enum):
    """Deterministic case status (no workflow state machine in this phase)."""

    OPEN = "open"
    TRIAGED = "triaged"
    CLOSED = "closed"


class CasePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class CaseID:
    """A content-derived case identity (hex SHA-256 of sorted inference ids)."""

    value: str

    @classmethod
    def of(cls, inference_ids: tuple[str, ...]) -> CaseID:
        payload = ",".join(sorted(inference_ids))
        return cls(hashlib.sha256(payload.encode("utf-8")).hexdigest())

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class InvestigationCase:
    """An immutable case grouping findings."""

    id: CaseID
    status: CaseStatus
    priority: CasePriority
    title: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    properties: PropertyBag = EMPTY_PROPERTIES

    def findings_of_kind(self, kind: str) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.kind.value == kind)

    def inference_ids(self) -> tuple[str, ...]:
        ids: set[str] = set()
        for finding in self.findings:
            ids.update(finding.explanation.inference_ids)
        return tuple(sorted(ids))

    def __len__(self) -> int:
        return len(self.findings)
