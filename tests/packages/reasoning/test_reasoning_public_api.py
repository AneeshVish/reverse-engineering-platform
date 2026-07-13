"""Invariant: the Phase 010 public API is frozen.

Everything exported from ``reveng_reasoning.__init__`` is the public API
established by Engineering Phase 010. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_reasoning as rz

PHASE_010_PUBLIC_API = frozenset(
    {
        "__version__",
        # inference model
        "InferenceKind",
        "InferenceState",
        "InferenceExplanation",
        "InferenceID",
        "Inference",
        "build_inference",
        # properties
        "PropertyKey",
        "PropertyValue",
        "PropertyBag",
        # rules
        "RuleID",
        "RuleRequirement",
        "RuleMetadata",
        "RuleContext",
        "RuleResult",
        "Rule",
        "DEFAULT_PRIORITY",
        # framework
        "RuleRegistry",
        "ReasoningPlanner",
        "ReasoningPlan",
        "RuleExecutor",
        "ReasoningEngine",
        "ReasoningResult",
        "ReasoningManager",
        "build_reasoning_engine",
        "register_builtin_rules",
        "REFERENCE_RULE_TYPES",
        # validation
        "validate_result",
        "ResultValidator",
        # serialization
        "ReasoningSerializer",
        "ReasoningDeserializer",
        # query
        "ReasoningQuery",
        "ReasoningQueryFilter",
        "ReasoningQueryResult",
        # contracts
        "ReasoningProvider",
        "ReasoningConsumer",
        "RuleProvider",
        # config
        "ReasoningConfig",
        "load_reasoning_config",
        "REASONING_DEFAULTS",
        # errors
        "ReasoningError",
        "RegistrationError",
        "RuleError",
        "ValidationError",
        "SerializationError",
        "IdentityError",
        "make_error",
        "guard",
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_010_PUBLIC_API - set(rz.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(rz.__all__) - PHASE_010_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_010_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in rz.__all__:
        assert hasattr(rz, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(rz.__all__) == len(set(rz.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in rz.__all__ if inspect.ismodule(getattr(rz, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
