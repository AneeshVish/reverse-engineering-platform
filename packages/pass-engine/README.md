# reveng-pass-engine

**Owner:** Implementation Specification 003 — Pass Execution Engine
**Status:** Implemented (Engineering Phase 005)
**Layer:** Execution framework; builds on `core-substrate` and `domain-producers`.

The pass engine is the platform's **execution framework**. It coordinates
analysis passes over normalized `Artifact`s — registration, dependency-graph
construction, deterministic planning, and synchronous scheduling. It performs
**no analysis** and never interprets what a pass produces.

## Responsibilities

- **Pass registration** — `PassRegistry` (authoritative, registration-ordered).
- **Dependency graph & planning** — `Planner` builds the graph over applicable
  passes and returns an immutable `ExecutionPlan` via a deterministic topological
  sort (Kahn's with registration-order tiebreak).
- **Synchronous scheduling** — `Scheduler` executes a plan in order on the calling
  thread with cooperative cancellation. No worker pools, async, or parallelism.
- **Results** — `PassResult` / `ExecutionReport`. A result's `payload` is
  **opaque** to the engine.

## Opaque payloads

`PassResult.payload` is typed `object | None`. The engine records it and hands it
back unchanged; it never inspects, interprets, or serializes it. Whether a pass
returns symbols, CFGs, IR, indicators, or anything else is entirely the concern of
later packages.

## Pass lifecycle

A `Pass` declares `PassMetadata` — identifier, version, capabilities,
prerequisites, dependencies, applicability, execution requirements — and
implements `run(context) -> PassResult`. The planner validates metadata,
dependency resolution, cycles, and prerequisites before anything executes. State
progresses `Registered → Planned → Running → Completed | Failed | Cancelled`.

Passes must be pure and deterministic: identical context ⇒ identical result. No
timestamps, randomness, or machine-specific behavior.

## Determinism

Given identical artifacts, registered passes, and configuration, the produced
`ExecutionPlan` and execution order are identical. Planning and scheduling contain
no timestamps, randomness, or machine-dependent ordering.

## Scheduling & failure model

Scheduling is synchronous and dependency-aware. A pass whose declared dependency
failed or was skipped is recorded `SKIPPED`; independent passes still run.
Failures are structured `PASS.*` errors (via `reveng_errors`) classified by
`FailureClass` (Transient/Permanent/Recoverable/Fatal). No raw exception escapes
the public API.

## Public interfaces

The public API is everything exported from `reveng_pass_engine.__init__`
(`__all__`). It is the frozen Phase 005 surface; later phases extend it additively
only.

## Extension mechanisms

- Register a pass with `PassEngineManager.register(...)` / `PassRegistry`.
- Declare ordering via `PassMetadata.dependencies`, gating via `prerequisites`,
  and scope via `applicability`.
- `build_engine()` wires a ready-to-use manager.

## Dependency rules

This package may depend only on `reveng-core-substrate`, `reveng-domain-producers`,
and the four engineering libs. It must never import another sibling package or any
app. The `pass-engine → domain-producers` edge is explicitly allowlisted in the
repository dependency validator.
