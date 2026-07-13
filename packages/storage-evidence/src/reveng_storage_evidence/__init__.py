"""reveng-storage-evidence — the canonical in-memory evidence store.

Owner: Implementation Specification 005 (Storage / Evidence). This package owns
storage contracts, versioned repositories, immutable evidence records, indexing,
exact-match querying, snapshots, and synchronous transactions. It performs no
reverse engineering, no persistence (no SQLite/PostgreSQL/filesystem DB), no
graph construction, and no reasoning. Everything is deterministic, synchronous,
and memory-resident.

Everything re-exported here constitutes the frozen Phase 007 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .config import STORAGE_DEFAULTS, StorageConfig, load_storage_config
from .contracts import EvidenceConsumer, EvidenceProvider, EvidenceStore
from .errors import (
    RepositoryError,
    SerializationError,
    StorageError,
    TransactionError,
    ValidationError,
    guard,
    make_error,
)
from .evidence import (
    Evidence,
    EvidenceConfidence,
    EvidenceID,
    EvidenceKind,
    EvidenceOrigin,
    EvidenceState,
    build_evidence,
)
from .indexing import ArtifactIndex, IdentityIndex, IRIndex, KindIndex
from .init import build_storage_manager
from .manager import StorageManager
from .metadata import MetadataBag, MetadataKey, MetadataValue
from .query import Query, QueryFilter, QueryResult
from .repository import EvidenceRepository
from .serialization import EvidenceDeserializer, EvidenceSerializer
from .snapshot import RepositorySnapshot, SnapshotBuilder
from .transactions import Transaction, TransactionResult, TransactionState
from .validation import RepositoryValidator, validate_index, validate_repository

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # evidence model
    "EvidenceID",
    "EvidenceKind",
    "EvidenceState",
    "EvidenceOrigin",
    "EvidenceConfidence",
    "Evidence",
    "build_evidence",
    # metadata
    "MetadataKey",
    "MetadataValue",
    "MetadataBag",
    # repository
    "EvidenceRepository",
    # indexing
    "IdentityIndex",
    "KindIndex",
    "ArtifactIndex",
    "IRIndex",
    # query
    "Query",
    "QueryFilter",
    "QueryResult",
    # snapshot
    "RepositorySnapshot",
    "SnapshotBuilder",
    # transactions
    "Transaction",
    "TransactionResult",
    "TransactionState",
    # validation
    "validate_repository",
    "validate_index",
    "RepositoryValidator",
    # serialization
    "EvidenceSerializer",
    "EvidenceDeserializer",
    # contracts
    "EvidenceStore",
    "EvidenceProvider",
    "EvidenceConsumer",
    # config
    "StorageConfig",
    "load_storage_config",
    "STORAGE_DEFAULTS",
    # manager
    "StorageManager",
    "build_storage_manager",
    # errors
    "StorageError",
    "RepositoryError",
    "TransactionError",
    "ValidationError",
    "SerializationError",
    "make_error",
    "guard",
]
