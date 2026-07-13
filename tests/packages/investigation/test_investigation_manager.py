"""Investigation tests: manager lifecycle, health, config, error conversion."""

from __future__ import annotations

from pathlib import Path

from _investigation_helpers import build_pipeline
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_investigation import (
    INVESTIGATION_DEFAULTS,
    CaseError,
    InvestigationConfig,
    InvestigationError,
    InvestigationManager,
    build_investigation_manager,
    guard,
    load_investigation_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = InvestigationManager()
    assert mgr.component_name == "investigation.manager"
    assert mgr.depends_on == ()


def test_participates_in_application_lifecycle() -> None:
    mgr = InvestigationManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    graph, repo, reasoning = build_pipeline()
    case = mgr.build(graph, repo, reasoning)
    assert mgr.serialize(case)
    app.shutdown()


def test_health() -> None:
    assert InvestigationManager().health_state() is HealthState.HEALTHY


def test_build_helper_and_view() -> None:
    mgr = build_investigation_manager()
    assert isinstance(mgr, InvestigationManager)
    graph, repo, reasoning = build_pipeline()
    view = mgr.build_view(graph, repo, reasoning)
    assert len(view.timeline) == len(view.case.findings)


def test_manager_run_validate_roundtrip() -> None:
    mgr = build_investigation_manager()
    graph, repo, reasoning = build_pipeline()
    case = mgr.build(graph, repo, reasoning)
    mgr.validate(case, graph, repo, reasoning)
    assert mgr.serialize(mgr.deserialize(mgr.serialize(case))) == mgr.serialize(case)


# --- config -----------------------------------------------------------------


def test_config_defaults() -> None:
    assert InvestigationConfig().get("validate_on_build") is True


def test_config_defaults_not_mutated() -> None:
    cfg = InvestigationConfig()
    cfg.values["validate_on_build"] = False
    assert INVESTIGATION_DEFAULTS["validate_on_build"] is True


def test_config_overrides() -> None:
    eng = EngConfig(values={"investigation": {"validate_on_build": False, "x": 1}})
    cfg = InvestigationConfig.from_eng_config(eng)
    assert cfg.get("validate_on_build") is False
    assert cfg.get("x") == 1


def test_config_non_mapping_ignored() -> None:
    cfg = InvestigationConfig.from_eng_config(EngConfig(values={"investigation": "nope"}))
    assert cfg.get("validate_on_build") is True


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.investigation]\nvalidate_on_build = false\n", encoding="utf-8"
    )
    assert load_investigation_config(tmp_path).get("validate_on_build") is False


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert InvestigationError.code == "INVESTIGATION.ERROR"
    assert CaseError.code == "INVESTIGATION.CASE"


def test_make_error() -> None:
    eng = make_error("INVESTIGATION.X", "m", a=1)
    assert eng.code == "INVESTIGATION.X"
    assert eng.context["a"] == 1


def test_guard_converts_investigation_error() -> None:
    def fail() -> int:
        raise CaseError("bad")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INVESTIGATION.CASE"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "INVESTIGATION.UNEXPECTED"
