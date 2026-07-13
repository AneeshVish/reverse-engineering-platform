"""IR tests: lifecycle participation, health, configuration, error conversion."""

from __future__ import annotations

from pathlib import Path

import pytest
from _ir_helpers import build_sample_module
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_intermediate_representation import (
    IR_DEFAULTS,
    ConstructionError,
    IRConfig,
    IRManager,
    ModuleBuilder,
    RepresentationError,
    SerializationError,
    ValidationError,
    build_ir_manager,
    guard,
    load_ir_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = IRManager()
    assert mgr.component_name == "intermediate-representation.manager"
    assert mgr.depends_on == ()


def test_participates_in_application_lifecycle() -> None:
    mgr = IRManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    module = mgr.module_builder("m").build()
    assert mgr.serialize(module)
    app.shutdown()


def test_health() -> None:
    assert IRManager().health_state() is HealthState.HEALTHY


def test_build_ir_manager_helper() -> None:
    mgr = build_ir_manager()
    assert isinstance(mgr, IRManager)


def test_manager_validate_and_roundtrip() -> None:
    mgr = build_ir_manager()
    module = build_sample_module()
    mgr.validate(module)
    assert mgr.serialize(mgr.deserialize(mgr.serialize(module))) == mgr.serialize(module)


# --- configuration ----------------------------------------------------------


def test_config_defaults() -> None:
    assert IRConfig().get("validate_on_build") is True


def test_config_defaults_not_mutated() -> None:
    cfg = IRConfig()
    cfg.values["validate_on_build"] = False
    assert IR_DEFAULTS["validate_on_build"] is True


def test_config_overrides() -> None:
    cfg = IRConfig.from_eng_config(EngConfig(values={"ir": {"validate_on_build": False, "x": 1}}))
    assert cfg.get("validate_on_build") is False
    assert cfg.get("x") == 1


def test_config_non_mapping_ignored() -> None:
    cfg = IRConfig.from_eng_config(EngConfig(values={"ir": "nope"}))
    assert cfg.get("validate_on_build") is True


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.ir]\nvalidate_on_build = false\n", encoding="utf-8"
    )
    assert load_ir_config(tmp_path).get("validate_on_build") is False


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert RepresentationError.code == "IR.REPRESENTATION"
    assert ValidationError.code == "IR.VALIDATION"
    assert ConstructionError.code == "IR.CONSTRUCTION"
    assert SerializationError.code == "IR.SERIALIZATION"


def test_make_error() -> None:
    eng = make_error("IR.X", "m", a=1)
    assert eng.code == "IR.X"
    assert eng.context["a"] == 1


def test_guard_converts_ir_error() -> None:
    result = guard(lambda: ModuleBuilder(""))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "IR.CONSTRUCTION"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "IR.UNEXPECTED"


def test_deserialize_invalid_raises_serialization_error() -> None:
    with pytest.raises(SerializationError):
        IRManager().deserialize("{not valid json")
