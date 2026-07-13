"""Storage tests: transactions — commit, rollback, atomicity."""

from __future__ import annotations

import pytest
from _storage_helpers import make_evidence
from reveng_storage_evidence import (
    EvidenceRepository,
    Transaction,
    TransactionError,
    TransactionState,
)


def test_commit_applies_all_operations() -> None:
    repo = EvidenceRepository()
    tx = Transaction(repo)
    tx.add(make_evidence("a"))
    tx.add(make_evidence("b"))
    result = tx.commit()
    assert result.ok
    assert result.state is TransactionState.COMMITTED
    assert result.applied == 2
    assert len(repo) == 2


def test_rollback_applies_nothing() -> None:
    repo = EvidenceRepository()
    tx = Transaction(repo)
    tx.add(make_evidence("a"))
    result = tx.rollback()
    assert result.state is TransactionState.ROLLED_BACK
    assert len(repo) == 0


def test_commit_is_atomic_on_failure() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a"))
    tx = Transaction(repo)
    tx.add(make_evidence("b"))  # would succeed
    tx.add(make_evidence("a"))  # duplicate → whole commit fails
    result = tx.commit()
    assert result.state is TransactionState.FAILED
    assert result.error is not None
    assert result.error.code == "STORAGE.REPOSITORY"
    # "b" must NOT have been applied — atomic all-or-nothing.
    assert len(repo) == 1


def test_replace_in_transaction() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a", payload={"v": 1}))
    tx = Transaction(repo)
    tx.replace(make_evidence("a", payload={"v": 2}))
    tx.commit()
    latest = repo.lookup(make_evidence("a").id)
    assert latest is not None
    assert latest.version == 2


def test_operations_after_commit_rejected() -> None:
    repo = EvidenceRepository()
    tx = Transaction(repo)
    tx.commit()
    with pytest.raises(TransactionError):
        tx.add(make_evidence("a"))


def test_double_commit_rejected() -> None:
    repo = EvidenceRepository()
    tx = Transaction(repo)
    tx.commit()
    with pytest.raises(TransactionError):
        tx.commit()
