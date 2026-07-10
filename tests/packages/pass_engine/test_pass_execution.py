"""Pass-engine tests: executor boundary, failure classes, opaque payloads."""

from __future__ import annotations

from _helpers import FailingPass, RecordingPass, ReturnFailurePass, make_request
from reveng_core_substrate import new_context
from reveng_pass_engine import (
    Executor,
    FailureClass,
    PassContext,
    PassResult,
    PassStatus,
)


def _ctx() -> PassContext:
    return PassContext(request=make_request(), execution_context=new_context())


def test_successful_pass_result_stamped_with_identifier() -> None:
    result = Executor().execute(RecordingPass("a", payload=None), _ctx())
    assert result.pass_id == "a"
    assert result.status is PassStatus.COMPLETED


def test_raised_exception_becomes_permanent_failure() -> None:
    result = Executor().execute(FailingPass("a"), _ctx())
    assert result.status is PassStatus.FAILED
    assert result.failure_class is FailureClass.PERMANENT
    assert result.error is not None
    assert result.error.code == "PASS.UNEXPECTED"


def test_no_raw_exception_escapes() -> None:
    # Executor must never propagate the pass's RuntimeError.
    result = Executor().execute(FailingPass("a"), _ctx())
    assert isinstance(result, PassResult)


def test_returned_failure_class_preserved() -> None:
    result = Executor().execute(
        ReturnFailurePass("a", failure_class=FailureClass.TRANSIENT), _ctx()
    )
    assert result.status is PassStatus.FAILED
    assert result.failure_class is FailureClass.TRANSIENT


def test_opaque_payload_round_trips_unchanged() -> None:
    sentinel = object()
    result = Executor().execute(RecordingPass("a", payload=sentinel), _ctx())
    # The engine hands back the exact object it was given, uninspected.
    assert result.payload is sentinel


def test_arbitrary_payload_types_round_trip() -> None:
    for payload in ({"symbols": [1, 2]}, [b"\x00"], ("cfg",), 42, "raw"):
        result = Executor().execute(RecordingPass("a", payload=payload), _ctx())
        assert result.payload == payload


def test_non_passresult_return_is_failure() -> None:
    class BadPass(RecordingPass):
        def run(self, context: PassContext):  # type: ignore[override]
            return "not a PassResult"

    result = Executor().execute(BadPass("a"), _ctx())
    assert result.status is PassStatus.FAILED
    assert result.error is not None
    assert result.error.code == "PASS.EXECUTION"
