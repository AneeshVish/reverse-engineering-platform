# reveng-plugin-sdk

**Owner:** Implementation Specification 009 — Plugin SDK
**Status:** Implemented (Engineering Phase 013)
**Layer:** Extension framework; the only package permitted to integrate with every backend subsystem.

The plugin SDK is the platform's **extension framework**. It provides deterministic
discovery, registration, dependency resolution, lifecycle management, capability
declaration, and a read-only execution context for third-party extensions. It
performs no analysis, reasoning, investigation, reporting, scheduling, persistence,
graph algorithms, or AI of its own.

## Passive plugins

Plugins are **passive**: they expose immutable capabilities against the platform's
extension points and are invoked by the owning managers. A plugin never invokes a
manager, owns storage or scheduling, or modifies platform state directly. All work
still flows through the existing managers.

## Plugin lifecycle

A `Plugin` exposes `metadata()`, `initialize()`, `shutdown()`, and `health()`. The
`PluginManager` (a substrate `Component`) discovers candidates, validates their
metadata, resolves dependency order, registers them, and drives their lifecycle in
dependency order (and shuts them down in reverse).

## Extension points & capabilities

A `CapabilityDescriptor` declares a `CapabilityKind` (producer, pass, analysis,
graph, reasoning, investigation, reporting, generic) hooking into an
`ExtensionPoint` (the registries/managers the backend already exposes). Metadata is
immutable.

## Deterministic loading

Discovery orders candidates by identifier; dependency resolution is a topological
sort with a registration-order tiebreak (missing dependencies and cycles raise
`DependencyError`). The same plugin set always yields the same registry, discovery
order, and load order. No timestamps, UUIDs, or randomness.

## Execution context (sandbox)

`PluginExecutionContext` is the immutable, read-only environment a manager hands a
plugin: a frozen configuration and the capabilities the plugin may use. There is no
OS/process isolation — the "sandbox" is the API boundary itself (process/VM
isolation is out of scope).

## Dependency rules

This package is intentionally the only one permitted to import **every** backend
subsystem: core-substrate, domain-producers, pass-engine,
intermediate-representation, storage-evidence, static-analysis, knowledge-graph,
reasoning, investigation, and reporting (plus the four engineering libs). No backend
may import the plugin SDK, and the SDK may not import apps or the upper-tier reserved
packages (public-api / deployment / observability). These edges are enforced by the
repository dependency validator.

## Naming note

The brief refers to this package as `plugins` / `reveng_plugins`; the reserved
workspace package is `plugin-sdk` / `reveng_plugin_sdk` (Implementation
Specification 009). Honoring the "no root workspace manifest changes" constraint,
this implementation fills the reserved `plugin-sdk` package. Likewise, the sandbox
context is `PluginExecutionContext` (not `ExecutionContext`) to avoid clashing with
the substrate's `ExecutionContext`.
