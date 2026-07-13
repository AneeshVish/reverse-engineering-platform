"""Plugin tests: dependency resolution, discovery, and sandbox."""

from __future__ import annotations

import pytest
from _plugin_helpers import MockPlugin, chain
from reveng_plugin_sdk import (
    CapabilityKind,
    DependencyError,
    DependencyResolver,
    PluginDiscovery,
    PluginExecutionContext,
    PropertyBag,
    resolve_load_order,
)


def test_load_order_respects_dependencies() -> None:
    assert resolve_load_order(chain()) == ("a", "b", "c")


def test_load_order_is_deterministic() -> None:
    plugins = chain()
    assert resolve_load_order(plugins) == resolve_load_order(plugins)


def test_missing_dependency_raises() -> None:
    with pytest.raises(DependencyError):
        resolve_load_order((MockPlugin("a", dependencies=("ghost",)),))


def test_cycle_raises() -> None:
    plugins = (
        MockPlugin("a", dependencies=("b",)),
        MockPlugin("b", dependencies=("a",)),
    )
    with pytest.raises(DependencyError):
        resolve_load_order(plugins)


def test_resolver_wrapper() -> None:
    assert DependencyResolver().resolve(chain()) == ("a", "b", "c")


def test_discovery_sorts_by_identifier() -> None:
    plugins = (MockPlugin("c"), MockPlugin("a"), MockPlugin("b"))
    order = tuple(p.identifier for p in PluginDiscovery().discover(plugins))
    assert order == ("a", "b", "c")


def test_repeated_discovery_identical() -> None:
    plugins = (MockPlugin("c"), MockPlugin("a"), MockPlugin("b"))
    disc = PluginDiscovery()
    assert [p.identifier for p in disc.discover(plugins)] == [
        p.identifier for p in disc.discover(plugins)
    ]


def test_execution_context_is_read_only() -> None:
    caps = MockPlugin("p", capability_names=("x",)).metadata().capabilities
    ctx = PluginExecutionContext(config=PropertyBag.of({"k": "v"}), capabilities=caps)
    assert ctx.has_capability("x")
    assert not ctx.has_capability("missing")
    assert ctx.capabilities_of_kind(CapabilityKind.GENERIC) == caps
    with pytest.raises((AttributeError, Exception)):
        ctx.capabilities = ()  # type: ignore[misc]
