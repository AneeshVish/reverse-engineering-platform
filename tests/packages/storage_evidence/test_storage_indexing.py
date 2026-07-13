"""Storage tests: indexes."""

from __future__ import annotations

from _storage_helpers import ir_id, make_evidence
from reveng_storage_evidence import (
    ArtifactIndex,
    EvidenceKind,
    EvidenceRepository,
    IdentityIndex,
    IRIndex,
    KindIndex,
)


def _repo():
    repo = EvidenceRepository()
    repo.add(
        make_evidence("a", kind=EvidenceKind.PROPERTY, artifact_ref="art1", ir_refs=(ir_id("a"),))
    )
    repo.add(make_evidence("b", kind=EvidenceKind.PROPERTY, artifact_ref="art1"))
    repo.add(make_evidence("c", kind=EvidenceKind.RELATION, ir_refs=(ir_id("a"), ir_id("b"))))
    return repo


def test_identity_index() -> None:
    repo = _repo()
    idx = repo.identity_index()
    for e in repo.enumerate():
        assert idx.contains(e.id)
    assert idx.ids() == tuple(sorted(idx.ids(), key=lambda i: i.value))


def test_kind_index() -> None:
    idx = _repo().kind_index()
    assert len(idx.lookup(EvidenceKind.PROPERTY)) == 2
    assert len(idx.lookup(EvidenceKind.RELATION)) == 1
    assert idx.lookup(EvidenceKind.RAW) == ()


def test_artifact_index() -> None:
    idx = _repo().artifact_index()
    assert len(idx.lookup("art1")) == 2
    assert idx.lookup("missing") == ()


def test_ir_index() -> None:
    idx = _repo().ir_index()
    assert len(idx.lookup(ir_id("a"))) == 2  # a and c reference ir "a"
    assert len(idx.lookup(ir_id("b"))) == 1
    assert idx.lookup(ir_id("z")) == ()


def test_indexes_are_deterministic() -> None:
    repo = _repo()
    assert repo.kind_index() == KindIndex.build(repo.enumerate())
    assert repo.artifact_index() == ArtifactIndex.build(repo.enumerate())
    assert repo.ir_index() == IRIndex.build(repo.enumerate())
    assert repo.identity_index() == IdentityIndex.build(repo.enumerate())
