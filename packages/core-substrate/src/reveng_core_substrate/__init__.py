"""reveng-core-substrate — foundational runtime substrate.

Owner: Implementation Specification 001 (Core Substrate). This package provides
infrastructure only: application lifecycle, dependency-injection container,
service/component/capability/feature/extension registries, execution context,
internal event dispatch, and health aggregation. It contains no reverse-
engineering, storage, scheduling, graph, reasoning, investigation, reporting,
plugin, or distributed-execution logic — those belong to Implementation
Specifications 002-014.

Everything re-exported here constitutes the frozen Phase 003 public API.
Later Engineering Phases must extend it additively.
"""

from __future__ import annotations

from .config import SUBSTRATE_DEFAULTS, SubstrateConfig, load_substrate_config
from .container import Lifetime, ServiceContainer
from .context import (
    ExecutionContext,
    current_context,
    new_context,
    use_context,
)
from .contracts import (
    Component,
    Disposable,
    HealthReport,
    HealthReporter,
    HealthState,
    Lifecycle,
    Service,
)
from .errors import (
    ConfigError,
    ContainerError,
    ContextError,
    EventError,
    LifecycleError,
    RegistryError,
    SubstrateError,
    guard,
    make_error,
)
from .events import Event, EventDispatcher, Subscriber
from .health import HealthAggregator, HealthCheck, HealthResult
from .lifecycle import Application, LifecycleHook, LifecycleState
from .registry import (
    CapabilityRegistry,
    ComponentRegistry,
    ExtensionRegistry,
    FeatureRegistry,
    KeyedRegistry,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # contracts
    "HealthState",
    "HealthReport",
    "Disposable",
    "Lifecycle",
    "Service",
    "Component",
    "HealthReporter",
    # errors
    "SubstrateError",
    "LifecycleError",
    "ContainerError",
    "RegistryError",
    "ContextError",
    "EventError",
    "ConfigError",
    "make_error",
    "guard",
    # container
    "Lifetime",
    "ServiceContainer",
    # registries
    "KeyedRegistry",
    "ComponentRegistry",
    "CapabilityRegistry",
    "FeatureRegistry",
    "ExtensionRegistry",
    # context
    "ExecutionContext",
    "current_context",
    "use_context",
    "new_context",
    # events
    "Event",
    "Subscriber",
    "EventDispatcher",
    # health
    "HealthResult",
    "HealthCheck",
    "HealthAggregator",
    # lifecycle
    "LifecycleState",
    "LifecycleHook",
    "Application",
    # config
    "SubstrateConfig",
    "load_substrate_config",
    "SUBSTRATE_DEFAULTS",
]
