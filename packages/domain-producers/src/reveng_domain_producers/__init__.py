"""reveng-domain-producers — artifact ingestion and normalization.

Owner: Implementation Specification 002 (Domain Producers). This package is the
production layer: it identifies supported artifact types, loads and validates
them, and emits normalized :class:`Artifact` objects. It performs no analysis —
no IR, static/dynamic analysis, storage, graph, reasoning, or persistence.

The registry is authoritative and open: built-in producers are the initial
reference set only, and third-party producers register through
:class:`ProducerFactory` on equal footing.

Everything re-exported here constitutes the frozen Phase 004 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .artifact import (
    Artifact,
    ArtifactIdentity,
    ArtifactSource,
    ArtifactState,
    ArtifactType,
    Provenance,
    build_artifact,
)
from .config import PRODUCER_DEFAULTS, ProducerConfig, load_producer_config
from .contracts import (
    DEFAULT_PRIORITY,
    CapabilityDescriptor,
    ClaimStrength,
    Producer,
    ProducerCapabilities,
    ProducerRequest,
    ProducerResult,
)
from .errors import (
    IdentificationError,
    ProducerError,
    ProductionError,
    RegistrationError,
    SelectionError,
    ValidationError,
    guard,
    make_error,
)
from .factory import ProducerFactory
from .identification import identify_type
from .manager import ProducerManager
from .producers import BaseProducer, register_builtin_producers
from .registry import ProducerRegistry
from .selection import select_producer

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # artifact contract
    "Artifact",
    "ArtifactType",
    "ArtifactState",
    "ArtifactSource",
    "ArtifactIdentity",
    "Provenance",
    "build_artifact",
    # producer contract
    "Producer",
    "BaseProducer",
    "ClaimStrength",
    "CapabilityDescriptor",
    "ProducerCapabilities",
    "ProducerRequest",
    "ProducerResult",
    "DEFAULT_PRIORITY",
    # framework
    "ProducerRegistry",
    "ProducerFactory",
    "ProducerManager",
    "identify_type",
    "select_producer",
    "register_builtin_producers",
    # config
    "ProducerConfig",
    "load_producer_config",
    "PRODUCER_DEFAULTS",
    # errors
    "ProducerError",
    "RegistrationError",
    "IdentificationError",
    "ValidationError",
    "SelectionError",
    "ProductionError",
    "make_error",
    "guard",
]
