# reveng-domain-producers

**Owner:** Implementation Specification 002 — Domain Producers
**Status:** Implemented (Engineering Phase 004)
**Layer:** Production/ingestion layer; builds on `packages/core-substrate`.

The domain producers package is the platform's **production layer**. It ingests
supported artifact types, identifies and validates them, and emits **normalized
`Artifact` objects** the rest of the platform consumes. It is not an analysis
layer: no IR, static/dynamic analysis, storage, graph, reasoning, or persistence
happens here.

## Responsibilities

- **Artifact identification** — shallow magic/extension sniffing to a candidate
  `ArtifactType` (advisory only).
- **Producer framework** — abstract `Producer` contract, `ProducerRegistry`
  (authoritative, deterministic order), `ProducerFactory` (open registration),
  and a thin `ProducerManager`.
- **Capability negotiation & selection** — producers issue a `ClaimStrength` for
  a source; selection is fully deterministic: **claim strength → priority →
  registration order**.
- **Normalized artifact production** — deterministic `Artifact` construction with
  content-derived identity and producer provenance.

## Producer lifecycle & registration

`ProducerManager` implements the substrate `Component` shape, so a host
`Application` initializes it (registering the reference producers) and shuts it
down cleanly. Producers register through `ProducerFactory`, which validates each
instance before it enters the `ProducerRegistry`.

The registry is authoritative and **open**: built-in producers are the initial
reference set only. `register_builtin_producers()` registers that reference set;
third-party producers register on equal footing and override a built-in for a
given source simply by declaring a higher `priority`.

## Producer contract

Every producer implements the full interface now, so later phases add behavior
without changing the contract:

```python
identify(request) -> ClaimStrength
validate(request) -> bool
produce(request)  -> ProducerResult
supported_capabilities() -> ProducerCapabilities
health() -> HealthResult
```

Producers MUST be pure and deterministic — no global state, timestamps, random
values, or machine-specific behavior. Identical input yields an identical
artifact.

## Public interfaces

The public API is everything exported from `reveng_domain_producers.__init__`
(`__all__`). It is the frozen Phase 004 surface; later phases extend it additively
only.

## Artifact contract

`Artifact` is an immutable contract accessed through properties and built only via
`build_artifact(...)` — never by instantiating the backing dataclass directly — so
future needs (lazy metadata, computed hashes, deferred loading, provenance
extensions) remain additive.

## Extension mechanisms

- Register a custom producer through `ProducerFactory.register(...)`.
- Advertise producer capabilities via `supported_capabilities()`.
- Override selection precedence via a producer's `priority`.

## Dependency rules

This package may depend only on `reveng-core-substrate` and the four engineering
libs (`reveng-types`, `reveng-errors`, `reveng-logging`, `reveng-config`). It must
never import another sibling package or any app.
