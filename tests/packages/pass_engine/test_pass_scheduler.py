"""Pass-engine tests: synchronous scheduling, failure propagation, cancellation."""

from __future__ import annotations

from _helpers import FailingPass, RecordingPass, make_request, result_of
from reveng_core_substrate import new_context
from reveng_pass_engine import (
    CancellationToken,
    ExecutionPlan,
    PassContext,
    PassRegistry,
    PassStatus,
    Planner,
    Scheduler,
)


def _run(passes, *, token=None):
    reg = PassRegistry()
    for p in passes:
        reg.register(p)
    req = make_request()
    plan = Planner().plan(reg, req)
    ctx = PassContext(request=req, execution_context=new_context())
    return Scheduler().run(plan, reg, ctx, token=token)


def test_executes_in_plan_order() -> None:
    log: list[str] = []
    report = _run(
        [
            RecordingPass("b", dependencies=("a",), log=log),
            RecordingPass("a", log=log),
        ]
    )
    assert log == ["a", "b"]
    assert all(r.status is PassStatus.COMPLETED for r in report.results)


def test_failed_pass_skips_dependents() -> None:
    log: list[str] = []
    report = _run(
        [
            FailingPass("a", log=log),
            RecordingPass("b", dependencies=("a",), log=log),
            RecordingPass("c", log=log),  # independent, still runs
        ]
    )
    assert result_of(report, "a").status is PassStatus.FAILED
    assert result_of(report, "b").status is PassStatus.SKIPPED
    assert result_of(report, "c").status is PassStatus.COMPLETED
    # b never actually ran; a and c did.
    assert "b" not in log
    assert "a" in log and "c" in log


def test_transitive_skip() -> None:
    report = _run(
        [
            FailingPass("a"),
            RecordingPass("b", dependencies=("a",)),
            RecordingPass("c", dependencies=("b",)),
        ]
    )
    assert result_of(report, "b").status is PassStatus.SKIPPED
    assert result_of(report, "c").status is PassStatus.SKIPPED


def test_report_not_ok_when_a_pass_fails() -> None:
    report = _run([FailingPass("a")])
    assert not report.ok


def test_cancellation_marks_remaining_cancelled() -> None:
    token = CancellationToken()
    token.cancel()  # cancelled before any pass runs
    log: list[str] = []
    report = _run([RecordingPass("a", log=log), RecordingPass("b", log=log)], token=token)
    assert result_of(report, "a").status is PassStatus.CANCELLED
    assert result_of(report, "b").status is PassStatus.CANCELLED
    assert log == []  # nothing executed


def test_empty_plan_yields_empty_report() -> None:
    reg = PassRegistry()
    ctx = PassContext(request=make_request(), execution_context=new_context())
    report = Scheduler().run(ExecutionPlan(), reg, ctx)
    assert report.results == ()
    assert report.ok


def test_scheduling_is_deterministic() -> None:
    passes = [
        RecordingPass("a"),
        RecordingPass("b", dependencies=("a",)),
        RecordingPass("c", dependencies=("a",)),
    ]
    first = _run(list(passes)).statuses()
    second = _run(list(passes)).statuses()
    assert first == second
