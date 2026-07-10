"""Pass-engine tests: substrate lifecycle participation and health."""

from __future__ import annotations

from _helpers import RecordingPass, make_request, result_of
from reveng_core_substrate import Application, HealthState
from reveng_pass_engine import PassEngineManager, PassStatus, build_engine


def test_manager_is_a_lifecycle_component() -> None:
    mgr = PassEngineManager()
    assert mgr.component_name == "pass-engine.manager"
    assert mgr.depends_on == ()


def test_participates_in_application_lifecycle() -> None:
    mgr = PassEngineManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    mgr.register(RecordingPass("a"))
    report = mgr.execute(make_request())
    assert result_of(report, "a").status is PassStatus.COMPLETED
    app.shutdown()


def test_build_engine_wires_a_usable_manager() -> None:
    mgr = build_engine()
    mgr.register(RecordingPass("a"))
    plan = mgr.plan(make_request())
    assert plan.ordered_ids == ("a",)


def test_health_reports_pass_count() -> None:
    mgr = PassEngineManager()
    assert mgr.health_state() is HealthState.HEALTHY
    mgr.register(RecordingPass("a"))
    assert "1 passes" in mgr.health().detail
