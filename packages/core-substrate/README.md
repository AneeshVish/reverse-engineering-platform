# reveng-core-substrate

**Owner:** Implementation Specification 001 — Core Substrate
**Status:** Implemented (Engineering Phase 003)
**Layer:** Lowest runtime layer — every other platform package builds on this one.

The core substrate is the foundational runtime infrastructure of the RevENG
platform. It provides the reusable machinery later packages depend on, and
nothing above it.

## Responsibilities

- **Application lifecycle** — an explicit state machine
  (`Created → Initializing → Ready → ShuttingDown → Stopped`, plus `Failed`) with
  dependency-ordered component initialization and reverse-order shutdown, and
  pre/post lifecycle hooks.
- **Dependency injection & service discovery** — `ServiceContainer` with
  instance, singleton, and factory registrations; missing/duplicate/cycle
  detection.
- **Registries** — component, capability, feature, and (plugin-independent)
  extension registries with deterministic enumeration.
- **Execution context** — `contextvars`-based correlation-id and scoped-value
  propagation, isolated per thread/task.
- **Internal event dispatch** — a synchronous, deterministic, failure-isolating
  event bus for substrate-internal signals.
- **Health** — health contracts and an aggregator that reduces component health
  to an overall state.
- **Integration** — configuration via `reveng-config`, structured logging via
  `reveng-logging`, error propagation via `reveng-errors`.

## Public interface

The public API is everything exported from `reveng_core_substrate.__init__`
(`__all__`). It is the frozen Phase 003 surface; later Engineering Phases extend
it **additively** and must not introduce breaking changes without a dedicated
migration phase.

## Lifecycle

```python
from reveng_core_substrate import Application

app = Application()
app.register_component(my_component)   # exposes component_name, depends_on, initialize, shutdown
app.initialize()                       # components initialized in dependency order
...
app.shutdown()                         # components shut down in reverse order
```

## Extension mechanisms

- Register lifecycle participants with `Application.register_component`.
- Advertise capabilities/features via `app.capabilities` / `app.features`.
- Expose extension points via `app.extensions` (the primitive the Plugin SDK,
  owned by a later phase, builds on — the substrate owns the mechanism, never
  the extensions).

## Dependency rules

This package may depend **only** on `reveng-types`, `reveng-errors`,
`reveng-logging`, and `reveng-config`. It must never import any `packages/*`
platform package or any app. It contains infrastructure only — no
reverse-engineering, storage, scheduling, graph, reasoning, investigation,
reporting, plugin, or distributed-execution logic (those are owned by
Implementation Specifications 002–014).
