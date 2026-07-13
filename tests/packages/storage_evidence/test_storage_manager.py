"""Storage tests: manager lifecycle, health, config, error conversion."""

from __future__ import annotations

from pathlib import Path

from _storage_helpers import make_evidence
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_storage_evidence import (
    STORAGE_DEFAULTS,
    RepositoryError,
    StorageConfig,
    StorageError,
    StorageManager,
    build_storage_manager,
    guard,
    load_storage_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = StorageManager()
    assert mgr.component_name == "storage-evidence.manager"
    assert mgr.depends_on == ()


def test_participates_in_application_lifecycle() -> None:
    mgr = StorageManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    mgr.add(make_evidence("a"))
    assert mgr.serialize()
    app.shutdown()


def test_health_reports_count() -> None:
    mgr = StorageManager()
    assert mgr.health_state() is HealthState.HEALTHY
    mgr.add(make_evidence("a"))
    assert "1 evidence records" in mgr.health().detail


def test_build_helper() -> None:
    assert isinstance(build_storage_manager(), StorageManager)


def test_manager_roundtrip() -> None:
    mgr = build_storage_manager()
    mgr.add(make_evidence("a", payload={"x": 1}))
    data = mgr.serialize()
    from reveng_storage_evidence import EvidenceSerializer

    assert EvidenceSerializer().serialize(mgr.deserialize(data)) == data


# --- config -----------------------------------------------------------------


def test_config_defaults() -> None:
    assert StorageConfig().get("validate_before_serialize") is True


def test_config_defaults_not_mutated() -> None:
    cfg = StorageConfig()
    cfg.values["validate_before_serialize"] = False
    assert STORAGE_DEFAULTS["validate_before_serialize"] is True


def test_config_overrides() -> None:
    cfg = StorageConfig.from_eng_config(
        EngConfig(values={"storage": {"validate_before_serialize": False, "x": 2}})
    )
    assert cfg.get("validate_before_serialize") is False
    assert cfg.get("x") == 2


def test_config_non_mapping_ignored() -> None:
    cfg = StorageConfig.from_eng_config(EngConfig(values={"storage": "nope"}))
    assert cfg.get("validate_before_serialize") is True


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.storage]\nvalidate_before_serialize = false\n", encoding="utf-8"
    )
    assert load_storage_config(tmp_path).get("validate_before_serialize") is False


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert StorageError.code == "STORAGE.ERROR"
    assert RepositoryError.code == "STORAGE.REPOSITORY"


def test_make_error() -> None:
    eng = make_error("STORAGE.X", "m", a=1)
    assert eng.code == "STORAGE.X"
    assert eng.context["a"] == 1


def test_guard_converts_storage_error() -> None:
    mgr = StorageManager()
    mgr.add(make_evidence("a"))
    result = guard(lambda: mgr.add(make_evidence("a")))  # duplicate
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "STORAGE.REPOSITORY"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "STORAGE.UNEXPECTED"
