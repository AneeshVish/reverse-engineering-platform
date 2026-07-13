"""Deterministic evidence indexes.

Each index is a plain dict-backed lookup with a ``build`` classmethod and
sorted, deterministic results. There are no search algorithms — indexes provide
exact-key access only. Indexes are rebuildable from a set of evidence, which the
repository maintains and validation cross-checks.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from reveng_intermediate_representation import IRIdentifier

from .evidence import Evidence, EvidenceID, EvidenceKind

__all__ = ["IdentityIndex", "KindIndex", "ArtifactIndex", "IRIndex"]


def _sorted_ids(ids: Iterable[EvidenceID]) -> tuple[EvidenceID, ...]:
    return tuple(sorted(set(ids), key=lambda e: e.value))


@dataclass(frozen=True)
class IdentityIndex:
    """Maps an evidence id to that evidence's id (membership/lookup)."""

    _ids: frozenset[EvidenceID] = field(default_factory=frozenset)

    @classmethod
    def build(cls, evidences: Iterable[Evidence]) -> IdentityIndex:
        return cls(frozenset(e.id for e in evidences))

    def contains(self, evidence_id: EvidenceID) -> bool:
        return evidence_id in self._ids

    def ids(self) -> tuple[EvidenceID, ...]:
        return _sorted_ids(self._ids)


@dataclass(frozen=True)
class KindIndex:
    """Maps an ``EvidenceKind`` to the evidence ids of that kind."""

    _by_kind: tuple[tuple[EvidenceKind, tuple[EvidenceID, ...]], ...] = ()

    @classmethod
    def build(cls, evidences: Iterable[Evidence]) -> KindIndex:
        buckets: dict[EvidenceKind, list[EvidenceID]] = {}
        for e in evidences:
            buckets.setdefault(e.kind, []).append(e.id)
        rows = tuple(
            (k, _sorted_ids(v)) for k, v in sorted(buckets.items(), key=lambda kv: kv[0].value)
        )
        return cls(rows)

    def lookup(self, kind: EvidenceKind) -> tuple[EvidenceID, ...]:
        for k, ids in self._by_kind:
            if k is kind:
                return ids
        return ()


@dataclass(frozen=True)
class ArtifactIndex:
    """Maps an artifact reference string to the evidence ids referencing it."""

    _by_ref: tuple[tuple[str, tuple[EvidenceID, ...]], ...] = ()

    @classmethod
    def build(cls, evidences: Iterable[Evidence]) -> ArtifactIndex:
        buckets: dict[str, list[EvidenceID]] = {}
        for e in evidences:
            if e.artifact_ref:
                buckets.setdefault(e.artifact_ref, []).append(e.id)
        rows = tuple((r, _sorted_ids(v)) for r, v in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, artifact_ref: str) -> tuple[EvidenceID, ...]:
        for r, ids in self._by_ref:
            if r == artifact_ref:
                return ids
        return ()


@dataclass(frozen=True)
class IRIndex:
    """Maps an IR identifier to the evidence ids referencing it."""

    _by_ir: tuple[tuple[str, tuple[EvidenceID, ...]], ...] = ()

    @classmethod
    def build(cls, evidences: Iterable[Evidence]) -> IRIndex:
        buckets: dict[str, list[EvidenceID]] = {}
        for e in evidences:
            for ref in e.ir_refs:
                buckets.setdefault(ref.value, []).append(e.id)
        rows = tuple((r, _sorted_ids(v)) for r, v in sorted(buckets.items()))
        return cls(rows)

    def lookup(self, ir_id: IRIdentifier) -> tuple[EvidenceID, ...]:
        for r, ids in self._by_ir:
            if r == ir_id.value:
                return ids
        return ()
