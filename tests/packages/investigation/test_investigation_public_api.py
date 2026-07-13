"""Invariant: the Phase 011 public API is frozen.

Everything exported from ``reveng_investigation.__init__`` is the public API
established by Engineering Phase 011. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_investigation as inv

PHASE_011_PUBLIC_API = frozenset(
    {
        "__version__",
        # finding model
        "FindingKind",
        "FindingSeverity",
        "FindingID",
        "FindingExplanation",
        "Finding",
        "build_finding",
        # case model
        "CaseStatus",
        "CasePriority",
        "CaseID",
        "InvestigationCase",
        # chains
        "InferenceChain",
        "EvidenceChain",
        "GraphChain",
        "chains_for",
        # timeline
        "Timeline",
        "build_timeline",
        # properties
        "PropertyKey",
        "PropertyValue",
        "PropertyBag",
        # builders
        "InvestigationBuilder",
        "InvestigationView",
        "REFERENCE_INVESTIGATION_TYPES",
        "run_reference_investigations",
        # validation
        "validate_case",
        "CaseValidator",
        # indexing
        "CaseIndex",
        "FindingIndex",
        "EvidenceIndex",
        "InferenceIndex",
        # query
        "InvestigationQuery",
        "InvestigationQueryFilter",
        "InvestigationQueryResult",
        # serialization
        "InvestigationSerializer",
        "InvestigationDeserializer",
        # contracts
        "InvestigationProvider",
        "InvestigationConsumer",
        # config
        "InvestigationConfig",
        "load_investigation_config",
        "INVESTIGATION_DEFAULTS",
        # manager
        "InvestigationManager",
        "build_investigation_manager",
        # errors
        "InvestigationError",
        "CaseError",
        "FindingError",
        "ValidationError",
        "SerializationError",
        "make_error",
        "guard",
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_011_PUBLIC_API - set(inv.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(inv.__all__) - PHASE_011_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_011_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in inv.__all__:
        assert hasattr(inv, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(inv.__all__) == len(set(inv.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in inv.__all__ if inspect.ismodule(getattr(inv, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
