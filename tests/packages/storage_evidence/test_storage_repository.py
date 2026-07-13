"""Storage tests: repository operations and versioning."""

from __future__ import annotations

import pytest
from _storage_helpers import make_evidence
from reveng_storage_evidence import EvidenceRepository, EvidenceState, RepositoryError


def test_add_and_lookup() -> None:
    repo = EvidenceRepository()
    ev = make_evidence("a")
    repo.add(ev)
    assert repo.lookup(ev.id) == ev
    assert repo.contains(ev.id)
    assert len(repo) == 1


def test_add_duplicate_rejected() -> None:
    repo = EvidenceRepository()
    repo.add(make_evidence("a"))
    with pytest.raises(RepositoryError):
        repo.add(make_evidence("a"))


def test_replace_creates_new_version_and_supersedes() -> None:
    repo = EvidenceRepository()
    ev = make_evidence("a", payload={"v": 1})
    repo.add(ev)
    new = repo.replace(make_evidence("a", payload={"v": 2}))
    assert new.version == 2
    assert new.state is EvidenceState.ACTIVE
    history = repo.history(ev.id)
    assert len(history) == 2
    assert history[0].state is EvidenceState.SUPERSEDED
    latest = repo.lookup(ev.id)
    assert latest is not None
    assert latest.version == 2


def test_replace_missing_rejected() -> None:
    repo = EvidenceRepository()
    with pytest.raises(RepositoryError):
        repo.replace(make_evidence("ghost"))


def test_remove() -> None:
    repo = EvidenceRepository()
    ev = make_evidence("a")
    repo.add(ev)
    repo.remove(ev.id)
    assert not repo.contains(ev.id)
    assert repo.lookup(ev.id) is None


def test_remove_missing_rejected() -> None:
    repo = EvidenceRepository()
    with pytest.raises(RepositoryError):
        repo.remove(make_evidence("x").id)


def test_enumerate_is_deterministic_by_id() -> None:
    repo = EvidenceRepository()
    for key in ("c", "a", "b"):
        repo.add(make_evidence(key))
    ids_first = [e.id.value for e in repo.enumerate()]
    ids_second = [e.id.value for e in repo.enumerate()]
    assert ids_first == ids_second == sorted(ids_first)


def test_enumerate_returns_latest_versions() -> None:
    repo = EvidenceRepository()
    ev = make_evidence("a", payload={"v": 1})
    repo.add(ev)
    repo.replace(make_evidence("a", payload={"v": 2}))
    (latest,) = repo.enumerate()
    assert latest.version == 2
