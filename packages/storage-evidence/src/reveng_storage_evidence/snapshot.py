"""Immutable repository snapshots.

A ``RepositorySnapshot`` is an immutable capture of a repository's latest
evidence at a point in time, in deterministic id order. Snapshots support
reproducible reads and comparison without touching the live repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import Evidence, EvidenceID
from .repository import EvidenceRepository

__all__ = ["RepositorySnapshot", "SnapshotBuilder"]


@dataclass(frozen=True)
class RepositorySnapshot:
    """An immutable, id-ordered capture of repository evidence."""

    evidence: tuple[Evidence, ...] = field(default_factory=tuple)

    def lookup(self, evidence_id: EvidenceID) -> Evidence | None:
        for e in self.evidence:
            if e.id == evidence_id:
                return e
        return None

    def ids(self) -> tuple[EvidenceID, ...]:
        return tuple(e.id for e in self.evidence)

    def __len__(self) -> int:
        return len(self.evidence)


class SnapshotBuilder:
    """Builds immutable snapshots from a repository."""

    def capture(self, repository: EvidenceRepository) -> RepositorySnapshot:
        return RepositorySnapshot(repository.enumerate())
