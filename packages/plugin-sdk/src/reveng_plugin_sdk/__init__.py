"""reveng-plugin-sdk — the platform's extension framework.

Owner: Implementation Specification 009 (Plugin SDK). This package provides
deterministic discovery, registration, dependency resolution, lifecycle
management, capability declaration, and a read-only execution context for
third-party extensions. Plugins are passive: they expose capabilities against the
platform's extension points and are invoked by the owning managers — they never
invoke managers, own storage or scheduling, or modify platform state. This package
performs no analysis, reasoning, investigation, reporting, or persistence of its
own.

Everything re-exported here constitutes the frozen Phase 013 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .capabilities import CapabilityDescriptor, CapabilityKind, ExtensionPoint
from .config import PLUGIN_DEFAULTS, PluginConfig, load_plugin_config
from .contracts import PluginConsumer, PluginFactory, PluginProvider
from .dependency import DependencyResolver, resolve_load_order
from .discovery import PluginDiscovery
from .errors import (
    DependencyError,
    LifecycleError,
    LoadingError,
    PluginError,
    RegistrationError,
    ValidationError,
    guard,
    make_error,
)
from .init import build_plugin_manager
from .loader import PluginLoader
from .manager import PluginManager
from .metadata import DEFAULT_PRIORITY, PluginMetadata
from .plugin import Plugin
from .properties import PropertyBag, PropertyKey, PropertyValue
from .reference import (
    REFERENCE_PLUGIN_TYPES,
    ExampleAnalysisPlugin,
    ExampleProducerPlugin,
    ExampleReportingPlugin,
    reference_plugins,
)
from .registry import PluginRegistry
from .sandbox import PluginExecutionContext
from .serialization import MetadataDeserializer, MetadataSerializer
from .validation import PluginValidator, validate_plugin, validate_plugins

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # metadata & capabilities
    "PluginMetadata",
    "DEFAULT_PRIORITY",
    "CapabilityKind",
    "ExtensionPoint",
    "CapabilityDescriptor",
    # properties
    "PropertyKey",
    "PropertyValue",
    "PropertyBag",
    # plugin & framework
    "Plugin",
    "PluginRegistry",
    "PluginDiscovery",
    "DependencyResolver",
    "resolve_load_order",
    "PluginLoader",
    "PluginExecutionContext",
    "PluginManager",
    "build_plugin_manager",
    # validation
    "validate_plugin",
    "validate_plugins",
    "PluginValidator",
    # serialization
    "MetadataSerializer",
    "MetadataDeserializer",
    # contracts
    "PluginProvider",
    "PluginConsumer",
    "PluginFactory",
    # reference plugins
    "ExampleProducerPlugin",
    "ExampleAnalysisPlugin",
    "ExampleReportingPlugin",
    "REFERENCE_PLUGIN_TYPES",
    "reference_plugins",
    # config
    "PluginConfig",
    "load_plugin_config",
    "PLUGIN_DEFAULTS",
    # errors
    "PluginError",
    "RegistrationError",
    "DependencyError",
    "ValidationError",
    "LoadingError",
    "LifecycleError",
    "make_error",
    "guard",
]
