"""Storage tests: repository and index validation."""

from __future__ import annotations

import pytest
from _storage_helpers import ir_id, make_evidence
from reveng_storage_evidence import (
    EvidenceRepository,
    KindIndex,
    ValidationError,
    validate_index,
    validate_repository,
)


def test_valid_repository_passes() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a"))
    validate_repository(repo)  # no raise


def test_dangling_ir_reference_rejected() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a", ir_refs=(ir_id("x"),)))
    with pytest.raises(ValidationError):
        validate_repository(repo, known_ir_ids=[ir_id("y")])  # x is not known


def test_known_ir_reference_passes() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a", ir_refs=(ir_id("x"),)))
    validate_repository(repo, known_ir_ids=[ir_id("x")])  # no raise


def test_consistent_index_passes() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a"))
    validate_index(repo, repo.kind_index())  # no raise


def test_broken_index_rejected() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a"))
    stale = KindIndex.build(())  # empty index, inconsistent with the repository
    with pytest.raises(ValidationError):
        validate_index(repo, stale)
