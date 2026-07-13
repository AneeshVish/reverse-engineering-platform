"""In-memory, versioned evidence repository.

Records are immutable; an update creates a new version and supersedes the prior
one. Enumeration order is deterministic (sorted by evidence id). Mutation is
guarded by a re-entrant lock. The repository maintains its indexes so they stay
consistent with its contents.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace

from .evidence import Evidence, EvidenceID, EvidenceState
from .errors import RepositoryError
from .indexing import ArtifactIndex, IdentityIndex, IRIndex, KindIndex

__all__ = ["EvidenceRepository"]


class EvidenceRepository:
    """A deterministic, versioned, in-memory store of evidence records."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[EvidenceID, list[Evidence]] = {}

    # -- mutation ------------------------------------------------------------

    def add(self, evidence: Evidence) -> None:
        """Add a new logical evidence record. Raises on a duplicate id."""

        with self._lock:
            if evidence.id in self._versions:
                raise RepositoryError("evidence already exists", id=evidence.id.value)
            self._versions[evidence.id] = [evidence]

    def replace(self, evidence: Evidence) -> Evidence:
        """Supersede the current version of ``evidence.id`` with a new version.

        Returns the newly-stored active record (version incremented). Raises if
        the logical id does not already exist.
        """

        with self._lock:
            chain = self._versions.get(evidence.id)
            if not chain:
                raise RepositoryError("evidence not found", id=evidence.id.value)
            chain[-1] = chain[-1].superseded()
            new_record = replace(
                evidence,
                version=chain[-1].version + 1,
                state=EvidenceState.ACTIVE,
            )
            chain.append(new_record)
            return new_record

    def remove(self, evidence_id: EvidenceID) -> None:
        """Remove all versions of a logical evidence id. Raises if absent."""

        with self._lock:
            if evidence_id not in self._versions:
                raise RepositoryError("evidence not found", id=evidence_id.value)
            del self._versions[evidence_id]

    def apply_atomically(self, work: Callable[[], None]) -> None:
        """Run ``work`` under the lock, restoring prior state on any exception.

        Because evidence records are immutable, saving shallow copies of the
        per-id version lists is a sufficient rollback point.
        """

        with self._lock:
            saved = {key: list(chain) for key, chain in self._versions.items()}
            try:
                work()
            except Exception:
                self._versions = saved
                raise

    # -- reads ---------------------------------------------------------------

    def lookup(self, evidence_id: EvidenceID) -> Evidence | None:
        """Return the latest version of ``evidence_id``, or ``None``."""

        with self._lock:
            chain = self._versions.get(evidence_id)
            return chain[-1] if chain else None

    def contains(self, evidence_id: EvidenceID) -> bool:
        with self._lock:
            return evidence_id in self._versions

    def history(self, evidence_id: EvidenceID) -> tuple[Evidence, ...]:
        """Return all versions of ``evidence_id`` in version order."""

        with self._lock:
            return tuple(self._versions.get(evidence_id, ()))

    def enumerate(self) -> tuple[Evidence, ...]:
        """Return the latest version of every record, sorted by id."""

        with self._lock:
            latest = [chain[-1] for chain in self._versions.values()]
        return tuple(sorted(latest, key=lambda e: e.id.value))

    def __len__(self) -> int:
        with self._lock:
            return len(self._versions)

    # -- indexes -------------------------------------------------------------

    def identity_index(self) -> IdentityIndex:
        return IdentityIndex.build(self.enumerate())

    def kind_index(self) -> KindIndex:
        return KindIndex.build(self.enumerate())

    def artifact_index(self) -> ArtifactIndex:
        return ArtifactIndex.build(self.enumerate())

    def ir_index(self) -> IRIndex:
        return IRIndex.build(self.enumerate())
