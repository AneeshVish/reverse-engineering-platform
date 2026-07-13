"""Plugin tests: manager lifecycle, health, config, and reference plugins."""

from __future__ import annotations

import pytest
from _plugin_helpers import MockPlugin
from reveng_core_substrate import Application, HealthState
from reveng_plugin_sdk import (
    PLUGIN_DEFAULTS,
    ExampleAnalysisPlugin,
    ExampleProducerPlugin,
    ExampleReportingPlugin,
    LoadingError,
    PluginConfig,
    PluginManager,
    build_plugin_manager,
    load_plugin_config,
    reference_plugins,
)


def test_manager_is_lifecycle_component() -> None:
    mgr = PluginManager(auto_load_reference=False)
    assert mgr.component_name == "plugin-sdk.manager"
    assert mgr.depends_on == ()


def test_reference_plugins_load_in_dependency_order() -> None:
    mgr = PluginManager()
    mgr.initialize()
    assert mgr.load_order() == ("example_producer", "example_analysis", "example_reporting")
    assert mgr.registry.contains("example_analysis")


def test_reference_plugins_helper() -> None:
    types = tuple(type(p) for p in reference_plugins())
    assert types == (ExampleProducerPlugin, ExampleAnalysisPlugin, ExampleReportingPlugin)


def test_participates_in_application_lifecycle() -> None:
    mgr = PluginManager()
    app = Application()
    app.register_component(mgr)
    app.initialize()
    assert len(mgr.registry) == 3
    app.shutdown()


def test_manager_health() -> None:
    mgr = PluginManager()
    mgr.initialize()
    assert mgr.health_state() is HealthState.HEALTHY
    assert "3 plugins" in mgr.health().detail


def test_execution_context_from_metadata() -> None:
    mgr = PluginManager()
    mgr.initialize()
    reporting = mgr.registry.get("example_reporting")
    ctx = mgr.execution_context(reporting)
    assert ctx.capabilities == reporting.metadata().capabilities


def test_reloading_same_plugin_raises_loading_error() -> None:
    mgr = PluginManager(auto_load_reference=False)
    mgr.load((MockPlugin("dup"),))
    with pytest.raises(LoadingError):
        mgr.load((MockPlugin("dup"),))


def test_build_plugin_manager() -> None:
    mgr = build_plugin_manager()
    assert isinstance(mgr, PluginManager)


def test_config_defaults() -> None:
    cfg = PluginConfig()
    assert cfg.get("load_reference_plugins") is True
    assert PLUGIN_DEFAULTS["load_reference_plugins"] is True


def test_load_plugin_config_from_repo(tmp_path) -> None:
    cfg = load_plugin_config(tmp_path)
    assert isinstance(cfg, PluginConfig)
