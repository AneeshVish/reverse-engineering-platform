"""Invariant: the Phase 005 public API is frozen.

Everything exported from ``reveng_pass_engine.__init__`` is the public API
established by Engineering Phase 005. Later phases extend it additively;
renames/removals and undeclared additions both fail here.
"""

from __future__ import annotations

import inspect

import reveng_pass_engine as engine

PHASE_005_PUBLIC_API = frozenset(
    {
        "__version__",
        # pass model
        "Pass",
        "PassMetadata",
        "PassState",
        # contracts
        "Capability",
        "Prerequisite",
        "Applicability",
        "ExecutionRequirements",
        "ExecutionRequest",
        "PassContext",
        # results
        "PassStatus",
        "FailureClass",
        "PassResult",
        "ExecutionReport",
        # framework
        "PassRegistry",
        "Planner",
        "ExecutionPlan",
        "Scheduler",
        "CancellationToken",
        "Executor",
        "Pipeline",
        "PassEngineManager",
        "build_engine",
        # config
        "PassEngineConfig",
        "load_pass_engine_config",
        "PASS_ENGINE_DEFAULTS",
        # errors
        "PassError",
        "RegistrationError",
        "PlanningError",
        "DependencyError",
        "PrerequisiteError",
        "ExecutionError",
        "CancellationError",
        "make_error",
        "guard",
    }
)


def test_no_removals_or_renames() -> None:
    missing = PHASE_005_PUBLIC_API - set(engine.__all__)
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_additions_are_recorded() -> None:
    added = set(engine.__all__) - PHASE_005_PUBLIC_API
    assert not added, f"new exports must be recorded in PHASE_005_PUBLIC_API: {sorted(added)}"


def test_every_export_importable() -> None:
    for name in engine.__all__:
        assert hasattr(engine, name), f"__all__ declares {name!r} but it is absent"


def test_all_has_no_duplicates() -> None:
    assert len(engine.__all__) == len(set(engine.__all__))


def test_no_submodules_exported() -> None:
    module_exports = [n for n in engine.__all__ if inspect.ismodule(getattr(engine, n))]
    assert not module_exports, f"submodules exported: {module_exports}"
