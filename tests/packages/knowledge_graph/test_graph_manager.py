"""Knowledge-graph tests: manager lifecycle, health, config, errors, immutability."""

from __future__ import annotations

from pathlib import Path

from _graph_helpers import build_sample
from reveng_config import EngConfig
from reveng_core_substrate import Application, HealthState
from reveng_knowledge_graph import (
    GRAPH_DEFAULTS,
    ConstructionError,
    GraphError,
    KnowledgeGraphConfig,
    KnowledgeGraphManager,
    build_knowledge_graph,
    guard,
    load_graph_config,
    make_error,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = KnowledgeGraphManager()
    assert mgr.component_name == "knowledge-graph.manager"
    assert mgr.depends_on == ()


def test_participates_in_application_lifecycle() -> None:
    mgr = KnowledgeGraphManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    ir, ev = build_sample()
    graph = mgr.build(ir, ev)
    assert mgr.serialize(graph)
    app.shutdown()


def test_health() -> None:
    assert KnowledgeGraphManager().health_state() is HealthState.HEALTHY


def test_build_helper() -> None:
    assert isinstance(build_knowledge_graph(), KnowledgeGraphManager)


def test_manager_roundtrip() -> None:
    mgr = build_knowledge_graph()
    ir, ev = build_sample()
    graph = mgr.build(ir, ev)
    assert mgr.serialize(mgr.deserialize(mgr.serialize(graph))) == mgr.serialize(graph)


def test_graph_is_immutable_and_evolves() -> None:
    ir, ev = build_sample()
    graph = KnowledgeGraphManager().build(ir, ev)
    evolved = graph.evolve(graph.nodes, graph.edges)
    assert evolved.version == graph.version + 1
    assert graph.version == 1  # original unchanged


# --- config -----------------------------------------------------------------


def test_config_defaults() -> None:
    assert KnowledgeGraphConfig().get("validate_on_build") is True


def test_config_defaults_not_mutated() -> None:
    cfg = KnowledgeGraphConfig()
    cfg.values["validate_on_build"] = False
    assert GRAPH_DEFAULTS["validate_on_build"] is True


def test_config_overrides() -> None:
    eng = EngConfig(values={"graph": {"validate_on_build": False, "x": 1}})
    cfg = KnowledgeGraphConfig.from_eng_config(eng)
    assert cfg.get("validate_on_build") is False
    assert cfg.get("x") == 1


def test_config_non_mapping_ignored() -> None:
    cfg = KnowledgeGraphConfig.from_eng_config(EngConfig(values={"graph": "nope"}))
    assert cfg.get("validate_on_build") is True


def test_load_config_reads_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.reveng.graph]\nvalidate_on_build = false\n", encoding="utf-8"
    )
    assert load_graph_config(tmp_path).get("validate_on_build") is False


# --- error conversion -------------------------------------------------------


def test_error_codes() -> None:
    assert GraphError.code == "GRAPH.ERROR"
    assert ConstructionError.code == "GRAPH.CONSTRUCTION"


def test_make_error() -> None:
    eng = make_error("GRAPH.X", "m", a=1)
    assert eng.code == "GRAPH.X"
    assert eng.context["a"] == 1


def test_guard_converts_graph_error() -> None:
    def fail() -> int:
        raise ConstructionError("bad")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "GRAPH.CONSTRUCTION"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "GRAPH.UNEXPECTED"
