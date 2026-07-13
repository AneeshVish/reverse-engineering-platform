"""Deterministic investigation indexes.

Dict-backed exact-lookup indexes with ``build`` classmethods and sorted,
deterministic results. No traversal or algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .case import InvestigationCase
from .finding import Finding

__all__ = ["CaseIndex", "FindingIndex", "EvidenceIndex", "InferenceIndex"]


@dataclass(frozen=True)
class CaseIndex:
    """Membership/lookup of the case id."""

    case_id: str = ""
    finding_ids: tuple[str, ...] = ()

    @classmethod
    def build(cls, case: InvestigationCase) -> CaseIndex:
        return cls(
            case_id=case.id.value,
            finding_ids=tuple(sorted(f.id.value for f in case.findings)),
        )

    def contains(self, case_id: str) -> bool:
        return case_id == self.case_id


@dataclass(frozen=True)
class FindingIndex:
    """Maps a finding id to that finding."""

    _by_id: tuple[tuple[str, Finding], ...] = ()

    @classmethod
    def build(cls, case: InvestigationCase) -> FindingIndex:
        rows = tuple(sorted(((f.id.value, f) for f in case.findings), key=lambda kv: kv[0]))
        return cls(rows)

    def get(self, finding_id: str) -> Finding | None:
        for fid, finding in self._by_id:
            if fid == finding_id:
                return finding
        return None

    def ids(self) -> tuple[str, ...]:
        return tuple(fid for fid, _ in self._by_id)


@dataclass(frozen=True)
class EvidenceIndex:
    """Maps an evidence id to the finding ids that reference it."""

    _by_evidence: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def build(cls, case: InvestigationCase) -> EvidenceIndex:
        buckets: dict[str, list[str]] = {}
        for finding in case.findings:
            for ev in finding.explanation.evidence_ids:
                buckets.setdefault(ev, []).append(finding.id.value)
        rows = tuple((ev, tuple(sorted(set(ids)))) for ev, ids in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, evidence_id: str) -> tuple[str, ...]:
        for ev, ids in self._by_evidence:
            if ev == evidence_id:
                return ids
        return ()


@dataclass(frozen=True)
class InferenceIndex:
    """Maps an inference id to the finding ids that reference it."""

    _by_inference: tuple[tuple[str, tuple[str, ...]], ...] = field(default_factory=tuple)

    @classmethod
    def build(cls, case: InvestigationCase) -> InferenceIndex:
        buckets: dict[str, list[str]] = {}
        for finding in case.findings:
            for inf in finding.explanation.inference_ids:
                buckets.setdefault(inf, []).append(finding.id.value)
        rows = tuple((inf, tuple(sorted(set(ids)))) for inf, ids in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, inference_id: str) -> tuple[str, ...]:
        for inf, ids in self._by_inference:
            if inf == inference_id:
                return ids
        return ()
