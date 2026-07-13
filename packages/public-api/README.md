# reveng-public-api

**Owner:** Implementation Specification 010 — Public API / Service Layer
**Status:** Implemented (Engineering Phase 014)
**Layer:** Outward-facing HTTP service layer; the platform's only FastAPI-based process.

The public API is the platform's REST/HTTP service layer. It orchestrates the
full ingestion-through-reporting pipeline — domain producers, static
analysis, storage, knowledge graph, reasoning, investigation, reporting — and
exposes read-only plugin listing from the plugin SDK, all over HTTP. **No
analysis logic lives here — pure orchestration.**

## What it exposes

- `POST /artifacts` — upload raw bytes, get back the produced `Artifact`'s
  identity and type.
- `POST /jobs` — upload raw bytes and kick off a full pipeline run in the
  background; returns a job id immediately.
- `GET /jobs/{job_id}` — non-blocking job status/progress.
- `GET /jobs/{job_id}/report` — the rendered report, once the job completes.
- `GET /plugins` — read-only listing of the registered plugins and their
  capabilities.
- `GET /health` — aggregated health across every wired backend manager.

Request bodies are validated by Pydantic models (`schemas.py`) — FastAPI
rejects malformed input with 422 before any handler runs.

## Dependency rules

This package is permitted to import: `domain-producers`, `pass-engine`,
`intermediate-representation`, `storage-evidence`, `static-analysis`,
`knowledge-graph`, `reasoning`, `investigation`, `reporting`, and
`plugin-sdk` (plus `core-substrate` and the four engineering libs).
`intermediate-representation` is included even though it isn't a "primary"
consumption target: the orchestrator's `PipelineResult` carries a typed
`IRModule` reference, the same non-optional-typing justification
`storage-evidence` and `knowledge-graph` already establish as precedent.

The reverse direction is closed: no backend package or the plugin SDK may
import `reveng_public_api`, and this package may not import `apps/*` or the
other upper-tier reserved siblings (`deployment`, `observability`,
`security`, `platform-validation`). Enforced by the repository dependency
validator and `tests/engineering/test_dep_layering.py`.

## The non-determinism exception

Every backend package in this platform is content-deterministic: no
timestamps, UUIDs, or randomness. This package **deliberately and narrowly**
breaks that rule, scoped to exactly one concern: job/session identity and
timing. Two byte-identical uploads submitted as separate jobs must get
distinct job ids, and progress genuinely changes over wall-clock time.

The pipeline orchestration itself (`orchestrator.py`) remains exactly as
deterministic as the nine backend packages it calls — given the same input
bytes, `PipelineOrchestrator.run` produces a bit-identical `PipelineResult`
every time. The exception is isolated behind two small, injectable seams
(`identifiers.py`): `IdProvider` (`MonotonicIdProvider` in production — a
counter, not a UUID, so ids are still fully predictable given a fixed
starting point) and `ClockProtocol` (`SystemClock` in production,
`FixedClock` in tests). No raw `uuid4()`/`datetime.now()` calls appear
anywhere else in the package.

## Job execution model

`JobManager` owns a bounded `concurrent.futures.ThreadPoolExecutor` (sized by
`job_pool_size`, default 4), created in `initialize()` and drained
(`wait=True`) in `shutdown()`. Submitting a job never blocks: it mints an id,
records a `PENDING` job under a lock, and hands the work to the pool.  Each
job's thread body runs the orchestrator *outside* the lock (so jobs don't
serialize each other) and only takes the lock briefly to record state
transitions (`PENDING → RUNNING → {COMPLETED, FAILED}`). Status/result reads
return snapshots (`dataclasses.replace`), never the live mutable `Job`, so a
polling client never observes a half-updated record. A failing job's
exception is caught at the job boundary and stored as a string — it never
escapes into the pool thread or leaks a raw traceback to a caller.

## Authentication hook

`auth.py` defines a framework-only seam: an `AuthHook` protocol and a
permissive `AllowAllAuthHook` default, wired as a FastAPI dependency on every
router except `/health`. It performs no real credential checking — it exists
so a later phase can supply real authentication without touching any route
signature.

## Composition

`init.py`'s `build_service()` is the single construction path: it wires all
nine backend managers plus the plugin manager into one
`reveng_core_substrate.Application` (so their existing `Component`
lifecycles handle initialization/shutdown uniformly), builds the
`PipelineOrchestrator` and `JobManager` on top, and returns a `ServiceContext`
shared by both `app.py` (`create_app()`) and the test suite.
