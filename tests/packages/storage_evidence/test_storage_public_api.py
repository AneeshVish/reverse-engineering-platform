"""Invariant: the Phase 007 public API is frozen.

Everything exported from ``reveng_storage_evidence.__init__`` is the public API
established by Engineering Phase 007. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_storage_evidence as storage

PHASE_007_PUBLIC_API = frozenset(
    {
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
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_007_PUBLIC_API - set(storage.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(storage.__all__) - PHASE_007_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_007_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in storage.__all__:
        assert hasattr(storage, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(storage.__all__) == len(set(storage.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in storage.__all__ if inspect.ismodule(getattr(storage, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
