"""Immutable project model.

A ``Project`` has no server-side counterpart -- Phase 014 has no ``/projects``
endpoint, projects are a purely local desktop construct. Its id is content-
derived from the root path (not a random UUID), staying close to this
platform's determinism ethos wherever a value has no server-assigned
identity to defer to.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

__all__ = ["Project"]


def _derive_project_id(root_path: Path) -> str:
    return hashlib.sha256(str(root_path).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Project:
    """An immutable, opened project: id, display name, root path, artifacts."""

    project_id: str
    name: str
    root_path: Path
    artifacts: tuple[str, ...] = field(default_factory=tuple)
    created_at: float = 0.0

    @classmethod
    def create(
        cls, root_path: Path, name: str | None = None, *, clock: Callable[[], float] = time.time
    ) -> Project:
        resolved = Path(root_path).resolve()
        return cls(
            project_id=_derive_project_id(resolved),
            name=name or resolved.name,
            root_path=resolved,
            created_at=clock(),
        )

    def with_artifact(self, artifact_ref: str) -> Project:
        if artifact_ref in self.artifacts:
            return self
        return replace(self, artifacts=(*self.artifacts, artifact_ref))
