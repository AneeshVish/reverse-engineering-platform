"""Domain-producer tests: producer-owned configuration."""

from __future__ import annotations

from pathlib import Path

from reveng_config import EngConfig
from reveng_domain_producers import (
    PRODUCER_DEFAULTS,
    ProducerConfig,
    load_producer_config,
)


def test_defaults_applied() -> None:
    cfg = ProducerConfig()
    assert cfg.get("enable_raw_fallback") is True


def test_defaults_constant_not_mutated() -> None:
    cfg = ProducerConfig()
    cfg.values["enable_raw_fallback"] = False
    assert PRODUCER_DEFAULTS["enable_raw_fallback"] is True


def test_from_eng_config_without_table_uses_defaults() -> None:
    cfg = ProducerConfig.from_eng_config(EngConfig(values={"python_version": "3.12"}))
    assert cfg.get("enable_raw_fallback") is True


def test_from_eng_config_overrides() -> None:
    eng = EngConfig(values={"producers": {"enable_raw_fallback": False, "extra": 9}})
    cfg = ProducerConfig.from_eng_config(eng)
    assert cfg.get("enable_raw_fallback") is False
    assert cfg.get("extra") == 9


def test_non_mapping_table_ignored() -> None:
    cfg = ProducerConfig.from_eng_config(EngConfig(values={"producers": "nope"}))
    assert cfg.get("enable_raw_fallback") is True


def test_load_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.producers]\nenable_raw_fallback = false\n",
        encoding="utf-8",
    )
    cfg = load_producer_config(tmp_path)
    assert cfg.get("enable_raw_fallback") is False
