"""Pass-engine tests: error taxonomy and boundary conversion."""

from __future__ import annotations

from _helpers import RecordingPass, make_request
from reveng_pass_engine import (
    CancellationError,
    DependencyError,
    ExecutionError,
    PassError,
    PassRegistry,
    Planner,
    PlanningError,
    PrerequisiteError,
    RegistrationError,
    guard,
    make_error,
)


def test_error_codes_namespaced() -> None:
    assert PassError.code == "PASS.ERROR"
    assert RegistrationError.code == "PASS.REGISTRATION"
    assert PlanningError.code == "PASS.PLANNING"
    assert DependencyError.code == "PASS.DEPENDENCY"
    assert PrerequisiteError.code == "PASS.PREREQUISITE"
    assert ExecutionError.code == "PASS.EXECUTION"
    assert CancellationError.code == "PASS.CANCELLED"


def test_to_eng_error_carries_context() -> None:
    eng = DependencyError("bad", pass_id="a", dependency="b").to_eng_error()
    assert eng.code == "PASS.DEPENDENCY"
    assert eng.context["dependency"] == "b"


def test_make_error() -> None:
    eng = make_error("PASS.X", "m", a=1)
    assert eng.code == "PASS.X"
    assert eng.context["a"] == 1


def test_guard_success() -> None:
    assert guard(lambda: 7).value == 7


def test_guard_converts_pass_error() -> None:
    def fail() -> int:
        raise PlanningError("bad", pass_id="a")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PASS.PLANNING"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PASS.UNEXPECTED"


def test_planner_errors_surface_through_guard() -> None:
    reg = PassRegistry()
    reg.register(RecordingPass("a", dependencies=("ghost",)))
    result = guard(lambda: Planner().plan(reg, make_request()))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PASS.DEPENDENCY"
