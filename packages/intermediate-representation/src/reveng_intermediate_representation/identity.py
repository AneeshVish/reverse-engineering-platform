"""Deterministic IR identity.

Every IR entity has a content-derived identity: a SHA-256 over its kind, its
hierarchical path, and its local content fields. Identity never depends on
timestamps, randomness, machine state, or the producer that built the IR — so
equivalent structures yield identical identifiers (canonical representation).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .errors import IdentityError

__all__ = ["IRNamespace", "IRPath", "IRIdentifier", "derive_identifier"]

_SEP = "\x00"


@dataclass(frozen=True)
class IRNamespace:
    """A hierarchical, dotted namespace (e.g. ``module.class``)."""

    parts: tuple[str, ...] = ()

    @classmethod
    def of(cls, *parts: str) -> IRNamespace:
        return cls(tuple(parts))

    def child(self, name: str) -> IRNamespace:
        return IRNamespace(self.parts + (name,))

    @property
    def qualified(self) -> str:
        return ".".join(self.parts)

    def __str__(self) -> str:
        return self.qualified


@dataclass(frozen=True)
class IRPath:
    """A path of hierarchy segments from the root to an entity.

    Segments encode the parent hierarchy, so identity composes hierarchically.
    """

    segments: tuple[str, ...] = ()

    @classmethod
    def root(cls) -> IRPath:
        return cls(())

    def child(self, segment: str) -> IRPath:
        return IRPath(self.segments + (segment,))

    @property
    def canonical(self) -> str:
        return "/".join(self.segments)

    def __str__(self) -> str:
        return self.canonical


@dataclass(frozen=True)
class IRIdentifier:
    """A content-derived identity (hex SHA-256)."""

    value: str

    @property
    def short(self) -> str:
        return self.value[:12]

    def __str__(self) -> str:
        return self.value


def derive_identifier(kind: str, path: IRPath, content: str = "") -> IRIdentifier:
    """Deterministically derive an identifier from kind, path, and content.

    The same three inputs always yield the same identifier; different inputs
    yield different identifiers with overwhelming probability.
    """

    if not kind:
        raise IdentityError("identity kind must be non-empty")
    digest = hashlib.sha256(_SEP.join((kind, path.canonical, content)).encode("utf-8"))
    return IRIdentifier(digest.hexdigest())
