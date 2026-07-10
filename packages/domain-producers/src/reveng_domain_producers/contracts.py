"""Producer contracts.

Defines the ``Producer`` interface and the value types used for capability
negotiation, selection, and results. The interface is deliberately complete now
(``identify``/``validate``/``produce``/``supported_capabilities``/``health``)
so later Engineering Phases add behavior without changing the contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum

from reveng_core_substrate import HealthResult

from .artifact import Artifact, ArtifactType

__all__ = [
    "ClaimStrength",
    "CapabilityDescriptor",
    "ProducerCapabilities",
    "ProducerRequest",
    "ProducerResult",
    "Producer",
    "DEFAULT_PRIORITY",
]

# Reference producers register at this priority; third-party producers override a
# built-in by declaring a higher value (see selection.py).
DEFAULT_PRIORITY = 100


class ClaimStrength(IntEnum):
    """How strongly a producer claims a given source.

    Ordered so a stronger claim compares greater, which selection relies on.
    """

    NONE = 0
    WEAK = 1
    STRONG = 2


@dataclass(frozen=True)
class CapabilityDescriptor:
    """A named capability a producer declares it can attach to an artifact."""

    name: str
    description: str = ""


@dataclass(frozen=True)
class ProducerCapabilities:
    """The set of capabilities a producer advertises."""

    descriptors: tuple[CapabilityDescriptor, ...] = ()

    def names(self) -> tuple[str, ...]:
        return tuple(d.name for d in self.descriptors)


@dataclass(frozen=True)
class ProducerRequest:
    """An ingestion request: raw content plus a stable source reference."""

    content: bytes
    source_ref: str
    hint_extension: str | None = None
    options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ProducerResult:
    """The outcome of a successful production."""

    artifact: Artifact


class Producer(ABC):
    """Abstract producer.

    Implementations must be pure and deterministic: identical requests must yield
    identical results, with no global state, timestamps, random values, or
    machine-specific behavior.
    """

    #: Stable producer name (registry key).
    name: str = ""
    #: Producer version, recorded in artifact provenance.
    version: str = "0.0.0"
    #: The artifact type this producer emits.
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    #: Selection priority; higher wins ties among equal claim strengths.
    priority: int = DEFAULT_PRIORITY

    @abstractmethod
    def identify(self, request: ProducerRequest) -> ClaimStrength:
        """Return how strongly this producer claims the request's source."""

    @abstractmethod
    def validate(self, request: ProducerRequest) -> bool:
        """Return whether the request's content is well-formed for this producer."""

    @abstractmethod
    def produce(self, request: ProducerRequest) -> ProducerResult:
        """Produce a normalized artifact from the request."""

    @abstractmethod
    def supported_capabilities(self) -> ProducerCapabilities:
        """Return the capabilities this producer advertises."""

    @abstractmethod
    def health(self) -> HealthResult:
        """Return this producer's current health."""
