"""The normalized artifact contract.

``Artifact`` is the immutable platform contract every producer emits and the rest
of the platform consumes. Consumers never construct the backing dataclass
directly — they read through accessors and build via :func:`build_artifact` — so
future needs (lazy metadata, computed hashes, deferred loading, provenance
extensions, cached capabilities) can be added additively behind the contract
without breaking callers.

Determinism: artifact identity is derived purely from the source content
(SHA-256), and provenance records only the producing producer's name/version and
a source reference. There are deliberately no timestamps, random identifiers, or
machine-specific values anywhere in the model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

__all__ = [
    "ArtifactType",
    "ArtifactState",
    "ArtifactSource",
    "ArtifactIdentity",
    "Provenance",
    "Artifact",
    "build_artifact",
]


class ArtifactType(str, Enum):
    """Normalized artifact categories the platform recognizes."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    APK = "apk"
    IPA = "ipa"
    DEX = "dex"
    JAR = "jar"
    DOTNET = "dotnet"
    FIRMWARE = "firmware"
    MEMORY_IMAGE = "memory_image"
    RAW_BINARY = "raw_binary"
    SOURCE_PROJECT = "source_project"
    UNKNOWN = "unknown"


class ArtifactState(str, Enum):
    """Lifecycle state of an artifact as it moves through production."""

    IDENTIFIED = "identified"
    LOADED = "loaded"
    VALIDATED = "validated"
    PRODUCED = "produced"


@dataclass(frozen=True)
class ArtifactSource:
    """Where an artifact came from, without binding to a live handle.

    ``ref`` is a stable, caller-supplied reference (e.g. a logical name or path
    string). It is never dereferenced by the model itself, keeping the contract
    free of filesystem dependence.
    """

    ref: str
    size: int


@dataclass(frozen=True)
class ArtifactIdentity:
    """Content-derived identity. Equal content yields equal identity."""

    content_hash: str

    @classmethod
    def from_content(cls, content: bytes) -> ArtifactIdentity:
        return cls(content_hash=hashlib.sha256(content).hexdigest())


@dataclass(frozen=True)
class Provenance:
    """How an artifact was produced — producer identity and source, no clock."""

    producer_name: str
    producer_version: str
    source_ref: str


@dataclass(frozen=True)
class _ArtifactData:
    identity: ArtifactIdentity
    source: ArtifactSource
    artifact_type: ArtifactType
    producer: str
    provenance: Provenance
    state: ArtifactState
    _metadata: Mapping[str, Any]
    _capabilities: tuple[str, ...]


class Artifact:
    """Immutable, read-only view over produced artifact data.

    The wrapped data is a frozen dataclass; this class exposes only accessors so
    the storage representation can evolve without changing the public contract.
    """

    __slots__ = ("_data",)

    def __init__(self, data: _ArtifactData) -> None:
        self._data = data

    @property
    def identity(self) -> ArtifactIdentity:
        return self._data.identity

    @property
    def source(self) -> ArtifactSource:
        return self._data.source

    @property
    def artifact_type(self) -> ArtifactType:
        return self._data.artifact_type

    @property
    def producer(self) -> str:
        return self._data.producer

    @property
    def provenance(self) -> Provenance:
        return self._data.provenance

    @property
    def state(self) -> ArtifactState:
        return self._data.state

    @property
    def metadata(self) -> Mapping[str, Any]:
        """Read-only metadata mapping."""

        return self._data._metadata

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Declared downstream capabilities (never computed by analysis here)."""

        return self._data._capabilities

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Artifact):
            return NotImplemented
        return self._data == other._data

    def __hash__(self) -> int:
        return hash(
            (
                self._data.identity,
                self._data.artifact_type,
                self._data.producer,
                self._data.state,
                self._data._capabilities,
                tuple(sorted(self._data._metadata.items())),
            )
        )

    def __repr__(self) -> str:
        return (
            f"Artifact(type={self._data.artifact_type.value}, "
            f"producer={self._data.producer!r}, "
            f"hash={self._data.identity.content_hash[:12]}…)"
        )


def build_artifact(
    *,
    content: bytes,
    source_ref: str,
    artifact_type: ArtifactType,
    producer_name: str,
    producer_version: str,
    metadata: Mapping[str, Any] | None = None,
    capabilities: tuple[str, ...] = (),
    state: ArtifactState = ArtifactState.PRODUCED,
) -> Artifact:
    """Construct an :class:`Artifact` deterministically from source content.

    Identity is the SHA-256 of ``content``; metadata is frozen into a read-only
    mapping; capabilities are recorded in the caller-supplied order. Given the
    same arguments this returns an equal artifact every time.
    """

    frozen_metadata: Mapping[str, Any] = MappingProxyType(dict(metadata or {}))
    data = _ArtifactData(
        identity=ArtifactIdentity.from_content(content),
        source=ArtifactSource(ref=source_ref, size=len(content)),
        artifact_type=artifact_type,
        producer=producer_name,
        provenance=Provenance(
            producer_name=producer_name,
            producer_version=producer_version,
            source_ref=source_ref,
        ),
        state=state,
        _metadata=frozen_metadata,
        _capabilities=capabilities,
    )
    return Artifact(data)
