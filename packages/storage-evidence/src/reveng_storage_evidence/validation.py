"""Repository validation.

Structural only: duplicate active identifiers, dangling IR references (against a
supplied set of known IR identifiers), and broken indexes (an index that does not
agree with one freshly built from the repository's contents).
"""

from __future__ import annotations

from collections.abc import Iterable

from reveng_intermediate_representation import IRIdentifier

from .errors import ValidationError
from .indexing import ArtifactIndex, IdentityIndex, IRIndex, KindIndex
from .repository import EvidenceRepository

__all__ = ["validate_repository", "validate_index", "RepositoryValidator"]


def validate_repository(
    repository: EvidenceRepository,
    *,
    known_ir_ids: Iterable[IRIdentifier] | None = None,
) -> None:
    """Validate a repository structurally, raising ``ValidationError``."""

    evidences = repository.enumerate()

    seen: set[str] = set()
    for e in evidences:
        if e.id.value in seen:
            raise ValidationError("duplicate evidence identifier", id=e.id.value)
        seen.add(e.id.value)

    if known_ir_ids is not None:
        known = {i.value for i in known_ir_ids}
        for e in evidences:
            for ref in e.ir_refs:
                if ref.value not in known:
                    raise ValidationError(
                        "dangling IR reference", id=e.id.value, ir_ref=ref.value
                    )


def validate_index(
    repository: EvidenceRepository,
    index: IdentityIndex | KindIndex | ArtifactIndex | IRIndex,
) -> None:
    """Verify an index agrees with one freshly built from the repository."""

    evidences = repository.enumerate()
    expected: IdentityIndex | KindIndex | ArtifactIndex | IRIndex
    if isinstance(index, IdentityIndex):
        expected = IdentityIndex.build(evidences)
    elif isinstance(index, KindIndex):
        expected = KindIndex.build(evidences)
    elif isinstance(index, ArtifactIndex):
        expected = ArtifactIndex.build(evidences)
    else:
        expected = IRIndex.build(evidences)
    if index != expected:
        raise ValidationError("index does not match repository contents")


class RepositoryValidator:
    """Object wrapper around the validation functions."""

    def validate(
        self,
        repository: EvidenceRepository,
        *,
        known_ir_ids: Iterable[IRIdentifier] | None = None,
    ) -> None:
        validate_repository(repository, known_ir_ids=known_ir_ids)
