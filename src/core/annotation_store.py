# -*- coding: utf-8 -*-
"""Local annotation overlay (Rename / Bookmark / Comment / Tag).

Desktop-local only -- never sent to the backend, since the platform's
Report/Artifact data is immutable by design. A rename or annotation applies
to a content-derived ``artifact_id`` (a SHA-256 of the loaded file's bytes,
see :func:`compute_artifact_id`), not a specific open session, so it survives
re-opening the same binary.

Shared-overlay rule (Phase 016 spec, 10.8): any component that displays
function identity must resolve names through this store rather than caching
or storing its own independent rename state.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from src.utils.paths import bundle_root, is_frozen, user_data_dir

logger = logging.getLogger(__name__)


class AnnotationKind(str, Enum):
    RENAME = "rename"
    BOOKMARK = "bookmark"
    COMMENT = "comment"
    TAG = "tag"


@dataclass
class Annotation:
    """{id, artifact_id, address, kind, payload, timestamp, version} -- fixed
    schema per the Phase 016 spec so a future payload-shape change has a
    field to branch on instead of needing a migration."""

    id: str
    artifact_id: str
    kind: AnnotationKind
    payload: str
    address: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    version: int = 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Annotation":
        return cls(
            id=data["id"],
            artifact_id=data["artifact_id"],
            kind=AnnotationKind(data["kind"]),
            payload=data["payload"],
            address=data.get("address"),
            timestamp=data.get("timestamp", 0.0),
            version=data.get("version", 1),
        )


def compute_artifact_id(content: bytes) -> str:
    """Content-derived id -- a rename survives re-opening the same binary."""
    return hashlib.sha256(content).hexdigest()


def _default_store_path() -> Path:
    base = user_data_dir() if is_frozen() else bundle_root()
    return base / "annotations.json"


class AnnotationStore:
    """JSON-persisted overlay of Rename/Bookmark/Comment/Tag annotations.

    Only Rename has UI in Phase 016 (via :meth:`rename`/:meth:`resolve_name`);
    Bookmark/Comment/Tag exist in the schema and this API but have no UI
    surface yet -- enabling them later is additive, not a redesign.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or _default_store_path()
        self._annotations: dict[str, Annotation] = {}
        self._counter = 0
        self.load()

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for item in data.get("annotations", []):
                ann = Annotation.from_dict(item)
                self._annotations[ann.id] = ann
            self._counter = data.get("counter", len(self._annotations))
        except Exception as e:  # noqa: BLE001 - best-effort load, never crash the app
            logger.error("Failed to load annotations: %s", e)

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "counter": self._counter,
                "annotations": [a.to_dict() for a in self._annotations.values()],
            }
            self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:  # noqa: BLE001 - best-effort save, never crash the app
            logger.error("Failed to save annotations: %s", e)

    def _new_id(self) -> str:
        self._counter += 1
        return f"ann-{self._counter:08d}"

    def add(
        self,
        artifact_id: str,
        kind: AnnotationKind,
        payload: str,
        address: Optional[int] = None,
    ) -> Annotation:
        ann = Annotation(
            id=self._new_id(),
            artifact_id=artifact_id,
            kind=kind,
            payload=payload,
            address=address,
            timestamp=time.time(),
        )
        self._annotations[ann.id] = ann
        self.save()
        return ann

    def remove(self, annotation_id: str) -> None:
        if annotation_id in self._annotations:
            del self._annotations[annotation_id]
            self.save()

    # -- rename -----------------------------------------------------------

    def rename(self, artifact_id: str, address: int, new_name: str) -> Annotation:
        """Set (replacing any prior rename at the same artifact+address)."""

        for ann_id, ann in list(self._annotations.items()):
            if (
                ann.kind == AnnotationKind.RENAME
                and ann.artifact_id == artifact_id
                and ann.address == address
            ):
                del self._annotations[ann_id]
        return self.add(artifact_id, AnnotationKind.RENAME, new_name, address=address)

    def resolve_name(self, artifact_id: str, address: int, original_name: str) -> str:
        """The renamed value at artifact+address, or original_name unchanged."""

        for ann in self._annotations.values():
            if (
                ann.kind == AnnotationKind.RENAME
                and ann.artifact_id == artifact_id
                and ann.address == address
            ):
                return ann.payload
        return original_name

    def renames_for_artifact(self, artifact_id: str) -> dict[int, str]:
        """address -> new_name for every rename in this artifact."""

        return {
            ann.address: ann.payload
            for ann in self._annotations.values()
            if ann.kind == AnnotationKind.RENAME
            and ann.artifact_id == artifact_id
            and ann.address is not None
        }

    def annotations_for(
        self, artifact_id: str, kind: Optional[AnnotationKind] = None
    ) -> tuple[Annotation, ...]:
        return tuple(
            a
            for a in self._annotations.values()
            if a.artifact_id == artifact_id and (kind is None or a.kind == kind)
        )
