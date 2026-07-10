"""Substrate invariant: the Phase 003 public API is frozen.

Everything exported from ``reveng_core_substrate.__init__`` constitutes the
public API established by Engineering Phase 003. Later Engineering Phases must
extend this surface **additively**; renames, signature-breaking changes, and
removals require a dedicated migration Engineering Phase.

This test pins the surface. Adding a new export is a one-line, deliberate edit
here. Removing or renaming one fails loudly.
"""

from __future__ import annotations

import inspect

import reveng_core_substrate as substrate

# The frozen Phase 003 public API. Extend additively; never remove or rename.
PHASE_003_PUBLIC_API = frozenset(
    {
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
    }
)


def test_public_api_has_no_removals_or_renames() -> None:
    exported = set(substrate.__all__)
    missing = PHASE_003_PUBLIC_API - exported
    assert not missing, f"public API removed or renamed (breaking change): {sorted(missing)}"


def test_public_api_additions_are_recorded() -> None:
    exported = set(substrate.__all__)
    added = exported - PHASE_003_PUBLIC_API
    assert not added, (
        "new public exports must be recorded in PHASE_003_PUBLIC_API "
        f"(additive is fine, undeclared is not): {sorted(added)}"
    )


def test_every_declared_export_is_importable() -> None:
    for name in substrate.__all__:
        assert hasattr(substrate, name), f"__all__ declares {name!r} but it is not present"


def test_all_has_no_duplicates() -> None:
    assert len(substrate.__all__) == len(set(substrate.__all__))


def test_no_private_names_exported() -> None:
    leaked = [n for n in substrate.__all__ if n.startswith("_") and n != "__version__"]
    assert not leaked, f"private names leaked into public API: {leaked}"


def test_internal_modules_are_not_re_exported_as_public_names() -> None:
    """The public surface is symbols, not submodules."""
    module_exports = [
        name for name in substrate.__all__ if inspect.ismodule(getattr(substrate, name))
    ]
    assert not module_exports, f"submodules exported as public API: {module_exports}"
