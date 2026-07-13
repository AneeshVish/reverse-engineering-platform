"""Static-analysis tests: manager lifecycle, health, config, error conversion."""

from __future__ import annotations

from pathlib import Path

from _static_helpers import make_request
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_static_analysis import (
    STATIC_DEFAULTS,
    AnalysisError,
    RegistrationError,
    StaticAnalysisConfig,
    StaticAnalysisManager,
    StaticError,
    build_static_analysis,
    guard,
    load_static_config,
    make_error,
)
from reveng_static_analysis.reference import BinaryHeaderAnalyzer


def test_manager_is_lifecycle_component() -> None:
    mgr = StaticAnalysisManager(auto_register_builtins=False)
    assert mgr.component_name == "static-analysis.manager"
    assert mgr.depends_on == ()


def test_initialize_registers_reference_analyzers() -> None:
    mgr = StaticAnalysisManager()
    assert len(mgr.registry) == 0
    mgr.initialize()
    assert len(mgr.registry) == 11


def test_participates_in_application_lifecycle() -> None:
    mgr = StaticAnalysisManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    report = mgr.analyze(make_request())
    assert report.module.nodes
    app.shutdown()


def test_build_helper() -> None:
    assert isinstance(build_static_analysis(), StaticAnalysisManager)


def test_health() -> None:
    mgr = StaticAnalysisManager(auto_register_builtins=False)
    assert mgr.health_state() is HealthState.HEALTHY
    mgr.register(BinaryHeaderAnalyzer())
    assert "1 analyzers" in mgr.health().detail


# --- config -----------------------------------------------------------------


def test_config_defaults() -> None:
    assert StaticAnalysisConfig().min_string_length() == 4


def test_config_defaults_not_mutated() -> None:
    cfg = StaticAnalysisConfig()
    cfg.values["min_string_length"] = 8
    assert STATIC_DEFAULTS["min_string_length"] == 4


def test_config_overrides() -> None:
    eng = EngConfig(values={"static": {"min_string_length": 6}})
    cfg = StaticAnalysisConfig.from_eng_config(eng)
    assert cfg.min_string_length() == 6


def test_config_non_mapping_ignored() -> None:
    cfg = StaticAnalysisConfig.from_eng_config(EngConfig(values={"static": "nope"}))
    assert cfg.min_string_length() == 4


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.static]\nmin_string_length = 7\n", encoding="utf-8"
    )
    assert load_static_config(tmp_path).min_string_length() == 7


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert StaticError.code == "STATIC.ERROR"
    assert AnalysisError.code == "STATIC.ANALYSIS"
    assert RegistrationError.code == "STATIC.REGISTRATION"


def test_make_error() -> None:
    eng = make_error("STATIC.X", "m", a=1)
    assert eng.code == "STATIC.X"
    assert eng.context["a"] == 1


def test_guard_converts_static_error() -> None:
    mgr = StaticAnalysisManager()
    mgr.initialize()
    result = guard(lambda: mgr.register(BinaryHeaderAnalyzer()))  # duplicate id
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "STATIC.REGISTRATION"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "STATIC.UNEXPECTED"
