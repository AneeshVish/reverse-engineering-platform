"""Reasoning tests: manager lifecycle, health, config, error conversion."""

from __future__ import annotations

from pathlib import Path

from _reasoning_helpers import build_sample
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_reasoning import (
    REASONING_DEFAULTS,
    ReasoningConfig,
    ReasoningError,
    ReasoningManager,
    RuleError,
    build_reasoning_engine,
    guard,
    load_reasoning_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = ReasoningManager(auto_register_builtins=False)
    assert mgr.component_name == "reasoning.manager"
    assert mgr.depends_on == ()


def test_initialize_registers_builtins() -> None:
    mgr = ReasoningManager()
    assert len(mgr.registry) == 0
    mgr.initialize()
    assert len(mgr.registry) == 10


def test_participates_in_application_lifecycle() -> None:
    mgr = ReasoningManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    graph, repo = build_sample()
    result = mgr.run(graph, repo)
    assert mgr.serialize(result)
    app.shutdown()


def test_build_helper_and_health() -> None:
    mgr = build_reasoning_engine()
    mgr.initialize()
    assert isinstance(mgr, ReasoningManager)
    assert mgr.health_state() is HealthState.HEALTHY
    assert "10 rules" in mgr.health().detail


def test_manager_run_validate_roundtrip() -> None:
    mgr = build_reasoning_engine()
    mgr.initialize()
    graph, repo = build_sample()
    result = mgr.run(graph, repo)
    mgr.validate(result, graph, repo)
    assert mgr.serialize(mgr.deserialize(mgr.serialize(result))) == mgr.serialize(result)


# --- config -----------------------------------------------------------------


def test_config_defaults_entry_symbols() -> None:
    assert "main" in ReasoningConfig().entry_symbols()


def test_config_defaults_not_mutated() -> None:
    cfg = ReasoningConfig()
    cfg.values["entry_symbols"] = ()
    assert "main" in REASONING_DEFAULTS["entry_symbols"]


def test_config_overrides() -> None:
    eng = EngConfig(values={"reasoning": {"entry_symbols": ["go"]}})
    cfg = ReasoningConfig.from_eng_config(eng)
    assert cfg.entry_symbols() == ("go",)


def test_config_non_mapping_ignored() -> None:
    cfg = ReasoningConfig.from_eng_config(EngConfig(values={"reasoning": "nope"}))
    assert "main" in cfg.entry_symbols()


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.reveng.reasoning]\nentry_symbols = ["boot"]\n', encoding="utf-8"
    )
    assert load_reasoning_config(tmp_path).entry_symbols() == ("boot",)


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert ReasoningError.code == "REASONING.ERROR"
    assert RuleError.code == "REASONING.RULE"


def test_make_error() -> None:
    eng = make_error("REASONING.X", "m", a=1)
    assert eng.code == "REASONING.X"
    assert eng.context["a"] == 1


def test_guard_converts_reasoning_error() -> None:
    def fail() -> int:
        raise RuleError("bad")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "REASONING.RULE"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "REASONING.UNEXPECTED"


def test_failing_rule_does_not_escape() -> None:
    # A rule that raises is isolated by the executor; the run still succeeds.
    from reveng_reasoning import RuleContext, RuleMetadata, RuleResult
    from reveng_reasoning.rules import Rule

    class Boom(Rule):
        @property
        def metadata(self) -> RuleMetadata:
            return RuleMetadata(identifier="boom")

        def apply(self, context: RuleContext) -> RuleResult:
            raise RuntimeError("kaboom")

    mgr = ReasoningManager(auto_register_builtins=False)
    mgr.register(Boom())
    graph, repo = build_sample()
    result = mgr.run(graph, repo)  # must not raise
    assert len(result) == 0
