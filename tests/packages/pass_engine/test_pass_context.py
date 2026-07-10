"""Pass-engine tests: execution context propagation."""

from __future__ import annotations

from _helpers import make_artifact, make_request
from reveng_core_substrate import current_context, new_context
from reveng_pass_engine import (
    Applicability,
    Pass,
    PassContext,
    PassMetadata,
    PassRegistry,
    PassResult,
    PassStatus,
    Pipeline,
)


def test_context_exposes_request_artifacts() -> None:
    art = make_artifact()
    ctx = PassContext(request=make_request(art), execution_context=new_context("cid"))
    assert ctx.artifacts == (art,)
    assert ctx.correlation_id == "cid"


def test_pipeline_binds_current_context_during_run() -> None:
    seen: dict[str, str] = {}

    class ProbePass(Pass):
        @property
        def metadata(self) -> PassMetadata:
            return PassMetadata(identifier="probe", version="1", applicability=Applicability())

        def run(self, context: PassContext) -> PassResult:
            # Both the passed context and the substrate current-context are bound.
            seen["ctx"] = context.correlation_id
            seen["current"] = current_context().correlation_id
            return PassResult("probe", PassStatus.COMPLETED)

    reg = PassRegistry()
    reg.register(ProbePass())
    ec = new_context("corr-1")
    Pipeline().execute(reg, make_request(), execution_context=ec)
    assert seen["ctx"] == "corr-1"
    assert seen["current"] == "corr-1"
