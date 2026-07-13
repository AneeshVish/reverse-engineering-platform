"""Simple synchronous transactions.

A ``Transaction`` stages add/replace/remove operations and applies them to a
repository atomically on ``commit`` (all-or-nothing under the repository lock).
``rollback`` discards staged operations without applying them. Transactions do
not nest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from reveng_errors import EngError

from .errors import TransactionError, guard
from .evidence import Evidence, EvidenceID
from .repository import EvidenceRepository

__all__ = ["TransactionState", "TransactionResult", "Transaction"]


class TransactionState(str, Enum):
    ACTIVE = "active"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass(frozen=True)
class TransactionResult:
    """The outcome of a commit or rollback."""

    state: TransactionState
    applied: int = 0
    error: EngError | None = None

    @property
    def ok(self) -> bool:
        return self.state is TransactionState.COMMITTED


@dataclass(frozen=True)
class _Op:
    kind: str  # "add" | "replace" | "remove"
    evidence: Evidence | None = None
    evidence_id: EvidenceID | None = None


class Transaction:
    """Stages operations and applies them atomically to a repository."""

    def __init__(self, repository: EvidenceRepository) -> None:
        self._repository = repository
        self._ops: list[_Op] = []
        self._state = TransactionState.ACTIVE

    @property
    def state(self) -> TransactionState:
        return self._state

    def _require_active(self) -> None:
        if self._state is not TransactionState.ACTIVE:
            raise TransactionError("transaction is not active", state=self._state.value)

    def add(self, evidence: Evidence) -> None:
        self._require_active()
        self._ops.append(_Op("add", evidence=evidence))

    def replace(self, evidence: Evidence) -> None:
        self._require_active()
        self._ops.append(_Op("replace", evidence=evidence))

    def remove(self, evidence_id: EvidenceID) -> None:
        self._require_active()
        self._ops.append(_Op("remove", evidence_id=evidence_id))

    def rollback(self) -> TransactionResult:
        """Discard staged operations without applying them."""

        self._require_active()
        self._ops.clear()
        self._state = TransactionState.ROLLED_BACK
        return TransactionResult(state=self._state)

    def commit(self) -> TransactionResult:
        """Apply all staged operations atomically."""

        self._require_active()
        ops = list(self._ops)

        def _apply() -> None:
            for op in ops:
                if op.kind == "add" and op.evidence is not None:
                    self._repository.add(op.evidence)
                elif op.kind == "replace" and op.evidence is not None:
                    self._repository.replace(op.evidence)
                elif op.kind == "remove" and op.evidence_id is not None:
                    self._repository.remove(op.evidence_id)

        outcome = guard(lambda: self._repository.apply_atomically(_apply))
        if outcome.ok:
            self._state = TransactionState.COMMITTED
            return TransactionResult(state=self._state, applied=len(ops))
        self._state = TransactionState.FAILED
        return TransactionResult(state=self._state, error=outcome.error)
