"""Pass-engine tests: planning, ordering, determinism, validation."""

from __future__ import annotations

import pytest
from _helpers import RecordingPass, make_artifact, make_request
from reveng_domain_producers import ArtifactType
from reveng_pass_engine import (
    DependencyError,
    ExecutionRequest,
    PassRegistry,
    Planner,
    PrerequisiteError,
)


def _registry(*passes: RecordingPass) -> PassRegistry:
    reg = PassRegistry()
    for p in passes:
        reg.register(p)
    return reg


def test_dependencies_ordered_before_dependents() -> None:
    reg = _registry(
        RecordingPass("c", dependencies=("b",)),
        RecordingPass("a"),
        RecordingPass("b", dependencies=("a",)),
    )
    plan = Planner().plan(reg, make_request())
    assert plan.ordered_ids == ("a", "b", "c")


def test_registration_order_breaks_ties() -> None:
    # Two independent passes → ordered by registration index, deterministically.
    reg = _registry(RecordingPass("z"), RecordingPass("y"))
    plan = Planner().plan(reg, make_request())
    assert plan.ordered_ids == ("z", "y")


def test_plan_is_deterministic_across_runs() -> None:
    passes = [
        RecordingPass("d", dependencies=("b", "c")),
        RecordingPass("b", dependencies=("a",)),
        RecordingPass("c", dependencies=("a",)),
        RecordingPass("a"),
    ]
    reg = _registry(*passes)
    req = make_request()
    plans = {Planner().plan(reg, req).ordered_ids for _ in range(10)}
    assert len(plans) == 1


def test_two_registries_same_order_same_plan() -> None:
    def build() -> PassRegistry:
        return _registry(
            RecordingPass("a"),
            RecordingPass("b", dependencies=("a",)),
            RecordingPass("c", dependencies=("a",)),
        )

    req = make_request()
    assert Planner().plan(build(), req).ordered_ids == Planner().plan(build(), req).ordered_ids


def test_unknown_dependency_raises() -> None:
    reg = _registry(RecordingPass("a", dependencies=("ghost",)))
    with pytest.raises(DependencyError):
        Planner().plan(reg, make_request())


def test_cycle_detected() -> None:
    reg = _registry(
        RecordingPass("a", dependencies=("b",)),
        RecordingPass("b", dependencies=("a",)),
    )
    with pytest.raises(DependencyError):
        Planner().plan(reg, make_request())


def test_prerequisite_satisfied_by_artifact_capability() -> None:
    reg = _registry(RecordingPass("a", requires=("sections",)))
    art = make_artifact(capabilities=("sections",))
    plan = Planner().plan(reg, ExecutionRequest(artifacts=(art,)))
    assert plan.ordered_ids == ("a",)


def test_prerequisite_satisfied_by_dependency_capability() -> None:
    reg = _registry(
        RecordingPass("provider", provides=("caps",)),
        RecordingPass("consumer", dependencies=("provider",), requires=("caps",)),
    )
    plan = Planner().plan(reg, make_request())
    assert plan.ordered_ids == ("provider", "consumer")


def test_unmet_prerequisite_raises() -> None:
    reg = _registry(RecordingPass("a", requires=("nope",)))
    with pytest.raises(PrerequisiteError):
        Planner().plan(reg, make_request())


def test_prerequisite_not_satisfied_by_incidental_ordering() -> None:
    # provider offers "caps" but consumer does NOT depend on it → unmet.
    reg = _registry(
        RecordingPass("provider", provides=("caps",)),
        RecordingPass("consumer", requires=("caps",)),
    )
    with pytest.raises(PrerequisiteError):
        Planner().plan(reg, make_request())


def test_applicability_filters_passes() -> None:
    reg = _registry(
        RecordingPass("pe_only", artifact_types=(ArtifactType.PE,)),
        RecordingPass("any"),
    )
    elf = make_artifact(ArtifactType.ELF)
    plan = Planner().plan(reg, ExecutionRequest(artifacts=(elf,)))
    assert plan.ordered_ids == ("any",)


def test_dependency_on_inapplicable_pass_raises() -> None:
    reg = _registry(
        RecordingPass("pe_only", artifact_types=(ArtifactType.PE,)),
        RecordingPass("dependent", dependencies=("pe_only",)),
    )
    elf = make_artifact(ArtifactType.ELF)
    with pytest.raises(DependencyError):
        Planner().plan(reg, ExecutionRequest(artifacts=(elf,)))


def test_empty_when_nothing_applies() -> None:
    reg = _registry(RecordingPass("pe_only", artifact_types=(ArtifactType.PE,)))
    plan = Planner().plan(reg, ExecutionRequest(artifacts=(make_artifact(ArtifactType.ELF),)))
    assert plan.ordered_ids == ()
