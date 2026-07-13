"""Invariant: the Phase 013 public API is frozen.

Pins ``reveng_plugin_sdk.__all__`` against an explicit snapshot so any addition or
removal is a deliberate, reviewed change. Later phases extend it additively.
"""

from __future__ import annotations

import reveng_plugin_sdk

PHASE_013_PUBLIC_API = frozenset(
    {
        "__version__",
        "PluginMetadata",
        "DEFAULT_PRIORITY",
        "CapabilityKind",
        "ExtensionPoint",
        "CapabilityDescriptor",
        "PropertyKey",
        "PropertyValue",
        "PropertyBag",
        "Plugin",
        "PluginRegistry",
        "PluginDiscovery",
        "DependencyResolver",
        "resolve_load_order",
        "PluginLoader",
        "PluginExecutionContext",
        "PluginManager",
        "build_plugin_manager",
        "validate_plugin",
        "validate_plugins",
        "PluginValidator",
        "MetadataSerializer",
        "MetadataDeserializer",
        "PluginProvider",
        "PluginConsumer",
        "PluginFactory",
        "ExampleProducerPlugin",
        "ExampleAnalysisPlugin",
        "ExampleReportingPlugin",
        "REFERENCE_PLUGIN_TYPES",
        "reference_plugins",
        "PluginConfig",
        "load_plugin_config",
        "PLUGIN_DEFAULTS",
        "PluginError",
        "RegistrationError",
        "DependencyError",
        "ValidationError",
        "LoadingError",
        "LifecycleError",
        "make_error",
        "guard",
    }
)


def test_public_api_matches_snapshot() -> None:
    assert frozenset(reveng_plugin_sdk.__all__) == PHASE_013_PUBLIC_API


def test_all_entries_are_importable() -> None:
    for name in reveng_plugin_sdk.__all__:
        assert hasattr(reveng_plugin_sdk, name), name


def test_all_has_no_duplicates() -> None:
    assert len(reveng_plugin_sdk.__all__) == len(set(reveng_plugin_sdk.__all__))
    assert len(reveng_plugin_sdk.__all__) == 42
