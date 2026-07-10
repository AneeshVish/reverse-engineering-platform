"""Pass-engine tests: engine-owned configuration."""

from __future__ import annotations

from pathlib import Path

from reveng_config import EngConfig
from reveng_pass_engine import (
    PASS_ENGINE_DEFAULTS,
    PassEngineConfig,
    load_pass_engine_config,
)


def test_defaults_applied() -> None:
    assert PassEngineConfig().get("skip_dependents_on_failure") is True


def test_defaults_constant_not_mutated() -> None:
    cfg = PassEngineConfig()
    cfg.values["skip_dependents_on_failure"] = False
    assert PASS_ENGINE_DEFAULTS["skip_dependents_on_failure"] is True


def test_from_eng_config_without_table_uses_defaults() -> None:
    cfg = PassEngineConfig.from_eng_config(EngConfig(values={"python_version": "3.12"}))
    assert cfg.get("skip_dependents_on_failure") is True


def test_from_eng_config_overrides() -> None:
    eng = EngConfig(values={"pass_engine": {"skip_dependents_on_failure": False, "extra": 3}})
    cfg = PassEngineConfig.from_eng_config(eng)
    assert cfg.get("skip_dependents_on_failure") is False
    assert cfg.get("extra") == 3


def test_non_mapping_table_ignored() -> None:
    cfg = PassEngineConfig.from_eng_config(EngConfig(values={"pass_engine": "nope"}))
    assert cfg.get("skip_dependents_on_failure") is True


def test_load_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.pass_engine]\nskip_dependents_on_failure = false\n",
        encoding="utf-8",
    )
    cfg = load_pass_engine_config(tmp_path)
    assert cfg.get("skip_dependents_on_failure") is False
