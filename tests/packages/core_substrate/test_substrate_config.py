"""Substrate tests: configuration loading via the shared engineering loader."""

from __future__ import annotations

import pytest
from reveng_config import EngConfig
from reveng_core_substrate import (
    SUBSTRATE_DEFAULTS,
    ConfigError,
    SubstrateConfig,
    load_substrate_config,
)


def test_defaults_applied() -> None:
    cfg = SubstrateConfig()
    assert cfg.get("strict_initialization") is True
    assert cfg.get("health_include_unknown") is True


def test_defaults_constant_is_not_mutated_by_instances() -> None:
    cfg = SubstrateConfig()
    cfg.values["strict_initialization"] = False
    assert SUBSTRATE_DEFAULTS["strict_initialization"] is True


def test_from_eng_config_without_substrate_table_uses_defaults() -> None:
    cfg = SubstrateConfig.from_eng_config(EngConfig(values={"python_version": "3.12"}))
    assert cfg.get("strict_initialization") is True


def test_from_eng_config_overrides_defaults() -> None:
    eng = EngConfig(values={"substrate": {"strict_initialization": False, "extra": 7}})
    cfg = SubstrateConfig.from_eng_config(eng)
    assert cfg.get("strict_initialization") is False
    assert cfg.get("extra") == 7
    # Untouched defaults survive the merge.
    assert cfg.get("health_include_unknown") is True


def test_from_eng_config_ignores_non_mapping_substrate_value() -> None:
    cfg = SubstrateConfig.from_eng_config(EngConfig(values={"substrate": "nonsense"}))
    assert cfg.get("strict_initialization") is True


def test_get_bool_accepts_bool_and_string_forms() -> None:
    cfg = SubstrateConfig(values={"a": True, "b": "yes", "c": "off", "d": "1"})
    assert cfg.get_bool("a") is True
    assert cfg.get_bool("b") is True
    assert cfg.get_bool("c") is False
    assert cfg.get_bool("d") is True


def test_get_bool_default_when_missing() -> None:
    cfg = SubstrateConfig(values={})
    assert cfg.get_bool("missing", default=True) is True


def test_get_bool_rejects_non_boolean() -> None:
    cfg = SubstrateConfig(values={"n": 12})
    with pytest.raises(ConfigError):
        cfg.get_bool("n")


def test_load_substrate_config_reads_repo(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.substrate]\nstrict_initialization = false\n",
        encoding="utf-8",
    )
    cfg = load_substrate_config(tmp_path)
    assert cfg.get("strict_initialization") is False
