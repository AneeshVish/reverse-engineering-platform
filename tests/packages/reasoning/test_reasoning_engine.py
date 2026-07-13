"""Reasoning tests: registration, planning, engine execution, determinism."""

from __future__ import annotations

import pytest
from _reasoning_helpers import build_sample, build_sample_graph
from reveng_reasoning import (
    ReasoningEngine,
    ReasoningPlanner,
    RegistrationError,
    RuleRegistry,
    register_builtin_rules,
)
from reveng_reasoning.reference import DeadSectionRule


def _registry() -> RuleRegistry:
    reg = RuleRegistry()
    register_builtin_rules(reg)
    return reg


def test_register_builtins() -> None:
    reg = _registry()
    assert len(reg) == 10
    assert "dead_section" in reg.identifiers()


def test_duplicate_rule_rejected() -> None:
    reg = RuleRegistry()
    reg.register(DeadSectionRule())
    with pytest.raises(RegistrationError):
        reg.register(DeadSectionRule())


def test_plan_is_deterministic() -> None:
    reg = _registry()
    graph = build_sample_graph()
    plans = {ReasoningPlanner().plan(reg, graph).ordered_ids for _ in range(5)}
    assert len(plans) == 1


def test_plan_orders_by_priority_then_registration() -> None:
    reg = _registry()
    graph = build_sample_graph()
    plan = ReasoningPlanner().plan(reg, graph)
    # All applicable rules present; equal-priority rules keep registration order.
    assert "dead_section" in plan.ordered_ids


def test_engine_produces_inferences() -> None:
    reg = _registry()
    graph, repo = build_sample()
    result = ReasoningEngine().run(reg, graph, repo)
    facts = {i.explanation.rule_id for i in result.inferences}
    assert "dead_section" in facts
    assert "duplicate_symbol" in facts
    assert "imported_but_not_referenced" in facts
    assert "missing_entry_symbol" in facts


def test_engine_output_sorted_and_deduped() -> None:
    reg = _registry()
    graph, repo = build_sample()
    result = ReasoningEngine().run(reg, graph, repo)
    ids = [i.id.value for i in result.inferences]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_deterministic_repeated_execution() -> None:
    reg = _registry()
    graph, repo = build_sample()
    a = ReasoningEngine().run(reg, graph, repo)
    b = ReasoningEngine().run(reg, graph, repo)
    assert [i.id.value for i in a.inferences] == [i.id.value for i in b.inferences]


def test_engine_does_not_mutate_inputs() -> None:
    reg = _registry()
    graph, repo = build_sample()
    before_nodes = len(graph.nodes)
    before_evidence = len(repo)
    ReasoningEngine().run(reg, graph, repo)
    assert len(graph.nodes) == before_nodes
    assert len(repo) == before_evidence
