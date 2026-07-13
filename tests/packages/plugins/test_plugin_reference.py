"""Plugin tests: reference plugins, capabilities, and contracts."""

from __future__ import annotations

from _plugin_helpers import MockPlugin
from reveng_plugin_sdk import (
    REFERENCE_PLUGIN_TYPES,
    CapabilityKind,
    ExtensionPoint,
    PluginConsumer,
    PluginFactory,
    PluginProvider,
    PluginRegistry,
    reference_plugins,
)


def test_reference_plugins_register() -> None:
    reg = PluginRegistry()
    for plugin in reference_plugins():
        reg.register(plugin)
    assert reg.identifiers() == (
        "example_producer",
        "example_analysis",
        "example_reporting",
    )


def test_reference_capabilities_span_extension_points() -> None:
    points = {
        cap.extension_point
        for plugin in reference_plugins()
        for cap in plugin.metadata().capabilities
    }
    assert points == {
        ExtensionPoint.PRODUCER_REGISTRY,
        ExtensionPoint.ANALYZER_REGISTRY,
        ExtensionPoint.REPORTING_TEMPLATE,
    }


def test_reference_capability_kinds() -> None:
    kinds = {cap.kind for plugin in reference_plugins() for cap in plugin.metadata().capabilities}
    assert kinds == {
        CapabilityKind.PRODUCER,
        CapabilityKind.ANALYSIS,
        CapabilityKind.REPORTING,
    }


def test_reference_types_fresh_instances() -> None:
    assert len(REFERENCE_PLUGIN_TYPES) == 3
    assert reference_plugins()[0] is not reference_plugins()[0]


def test_reference_default_health() -> None:
    for plugin in reference_plugins():
        assert plugin.health().state.name == "HEALTHY"


class _Provider:
    def provide(self) -> tuple:
        return reference_plugins()


class _Consumer:
    def consume(self, plugin) -> None:  # noqa: ANN001
        pass


class _Factory:
    def create(self):  # noqa: ANN201
        return MockPlugin("made")


def test_contracts_are_runtime_checkable() -> None:
    assert isinstance(_Provider(), PluginProvider)
    assert isinstance(_Consumer(), PluginConsumer)
    assert isinstance(_Factory(), PluginFactory)
