"""Reporting tests: manager lifecycle, health, config, error conversion."""

from __future__ import annotations

from pathlib import Path

import pytest
from _reporting_helpers import build_pipeline
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_reporting import (
    REPORTING_DEFAULTS,
    BuilderError,
    RenderFormat,
    ReportingConfig,
    ReportingError,
    ReportingManager,
    TemplateError,
    build_reporting_manager,
    guard,
    load_reporting_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = ReportingManager(auto_register_templates=False)
    assert mgr.component_name == "reporting.manager"
    assert mgr.depends_on == ()


def test_initialize_registers_templates() -> None:
    mgr = ReportingManager()
    assert mgr.template_names() == ()
    mgr.initialize()
    assert len(mgr.template_names()) == 5


def test_participates_in_application_lifecycle() -> None:
    mgr = ReportingManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    case, reasoning, repo, graph = build_pipeline()
    report = mgr.build(case, reasoning, repo, graph, "technical")
    assert mgr.render(report, RenderFormat.JSON)
    app.shutdown()


def test_health() -> None:
    mgr = ReportingManager()
    mgr.initialize()
    assert mgr.health_state() is HealthState.HEALTHY
    assert "5 templates" in mgr.health().detail


def test_build_helper_default_template() -> None:
    mgr = build_reporting_manager()
    mgr.initialize()
    case, reasoning, repo, graph = build_pipeline()
    report = mgr.build(case, reasoning, repo, graph)
    assert report.template == "executive_summary"


def test_unknown_template_raises() -> None:
    mgr = ReportingManager()
    mgr.initialize()
    with pytest.raises(TemplateError):
        mgr.template("nonexistent")


def test_manager_roundtrip_and_validate() -> None:
    mgr = build_reporting_manager()
    mgr.initialize()
    case, reasoning, repo, graph = build_pipeline()
    report = mgr.build(case, reasoning, repo, graph, "technical")
    mgr.validate(report, case, reasoning, repo, graph)
    assert mgr.serialize(mgr.deserialize(mgr.serialize(report))) == mgr.serialize(report)


# --- config -----------------------------------------------------------------


def test_config_default_template() -> None:
    assert ReportingConfig().default_template() == "executive_summary"


def test_config_defaults_not_mutated() -> None:
    cfg = ReportingConfig()
    cfg.values["default_template"] = "technical"
    assert REPORTING_DEFAULTS["default_template"] == "executive_summary"


def test_config_overrides() -> None:
    eng = EngConfig(values={"reporting": {"default_template": "technical"}})
    cfg = ReportingConfig.from_eng_config(eng)
    assert cfg.default_template() == "technical"


def test_config_non_mapping_ignored() -> None:
    cfg = ReportingConfig.from_eng_config(EngConfig(values={"reporting": "nope"}))
    assert cfg.default_template() == "executive_summary"


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.reveng.reporting]\ndefault_template = "evidence"\n', encoding="utf-8"
    )
    assert load_reporting_config(tmp_path).default_template() == "evidence"


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert ReportingError.code == "REPORT.ERROR"
    assert BuilderError.code == "REPORT.BUILDER"
    assert TemplateError.code == "REPORT.TEMPLATE"


def test_make_error() -> None:
    eng = make_error("REPORT.X", "m", a=1)
    assert eng.code == "REPORT.X"
    assert eng.context["a"] == 1


def test_guard_converts_reporting_error() -> None:
    def fail() -> int:
        raise BuilderError("bad")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "REPORT.BUILDER"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "REPORT.UNEXPECTED"
