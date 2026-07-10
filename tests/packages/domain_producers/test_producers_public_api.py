"""Invariant: the Phase 004 public API is frozen.

Everything exported from ``reveng_domain_producers.__init__`` is the public API
established by Engineering Phase 004. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_domain_producers as producers

PHASE_004_PUBLIC_API = frozenset(
    {
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
    }
)


def test_no_removals_or_renames() -> None:
    exported = set(producers.__all__)
    missing = PHASE_004_PUBLIC_API - exported
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    exported = set(producers.__all__)
    added = exported - PHASE_004_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_004_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in producers.__all__:
        assert hasattr(producers, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(producers.__all__) == len(set(producers.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in producers.__all__ if inspect.ismodule(getattr(producers, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
