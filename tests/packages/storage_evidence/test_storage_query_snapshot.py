"""Storage tests: query and snapshots."""

from __future__ import annotations

from _storage_helpers import ir_id, make_evidence
from reveng_storage_evidence import (
    EvidenceConfidence,
    EvidenceKind,
    EvidenceRepository,
    Query,
    QueryFilter,
    SnapshotBuilder,
)


def _repo():
    repo = EvidenceRepository()
    repo.add(
        make_evidence(
            "a",
            kind=EvidenceKind.PROPERTY,
            confidence=EvidenceConfidence.OBSERVED,
            artifact_ref="art1",
        )
    )
    repo.add(
        make_evidence(
            "b",
            kind=EvidenceKind.RELATION,
            confidence=EvidenceConfidence.MEASURED,
            ir_refs=(ir_id("x"),),
        )
    )
    return repo


def test_query_by_kind() -> None:
    result = Query((QueryFilter(kind=EvidenceKind.PROPERTY),)).run(_repo())
    assert len(result) == 1


def test_query_conjunction() -> None:
    repo = _repo()
    q = Query((QueryFilter(kind=EvidenceKind.PROPERTY), QueryFilter(artifact_ref="art1")))
    assert len(q.run(repo)) == 1
    q2 = Query((QueryFilter(kind=EvidenceKind.PROPERTY), QueryFilter(artifact_ref="none")))
    assert len(q2.run(repo)) == 0


def test_query_by_ir_ref() -> None:
    result = Query((QueryFilter(ir_ref=ir_id("x")),)).run(_repo())
    assert len(result) == 1


def test_empty_query_returns_all_in_order() -> None:
    repo = _repo()
    result = Query(()).run(repo)
    assert result.ids() == tuple(e.id.value for e in repo.enumerate())


def test_query_result_is_deterministic() -> None:
    repo = _repo()
    q = Query(())
    assert q.run(repo).ids() == q.run(repo).ids()


def test_snapshot_captures_state() -> None:
    repo = _repo()
    snap = SnapshotBuilder().capture(repo)
    assert len(snap) == 2
    assert snap.ids() == tuple(e.id for e in repo.enumerate())


def test_snapshot_is_stable_after_repo_mutation() -> None:
    repo = _repo()
    snap = SnapshotBuilder().capture(repo)
    repo.add(make_evidence("c"))
    # Snapshot is immutable; it does not observe the later addition.
    assert len(snap) == 2
