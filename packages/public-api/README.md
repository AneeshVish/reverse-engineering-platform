# reveng-public-api

**Owner:** Implementation Specification 010 — Public API / Service Layer
**Status:** Implemented (Engineering Phase 014; extended additively by Engineering Phase 017 — Pipeline Query API)
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
- `GET /jobs/{job_id}` — non-blocking job detail: state, timing, current
  phase, per-phase timings, progress percentage, cancellation state, and
  whether a report is available. A strict superset of the original Phase 014
  `JobStatusResponse` fields — nothing removed or renamed.
- `GET /jobs/{job_id}/report` — the rendered report, once the job completes.
- `GET /plugins` — read-only listing of the registered plugins and their
  capabilities.
- `GET /health` — aggregated health across every wired backend manager.

**Engineering Phase 017 — Pipeline Query API** (additive; no Phase 014 route
or schema was removed or changed shape):

- `GET /jobs` — job history: filter by `state`, `project` (an exact match on
  the `source_ref` the desktop tagged the job with — the backend has no
  native Project entity, so this parameter is a documented alias, not a real
  backend concept), `artifact` (exact match on `artifact_ref`, known as soon
  as the static-analysis phase completes — see below), `created_after`/
  `created_before`; paginated (`limit`/`offset`/`total_count`), newest-first.
- `DELETE /jobs/{job_id}` — cancel a job. `Pending` jobs are cancelled
  immediately; `Running` jobs are cancelled **cooperatively** (see below);
  jobs already in a terminal state return 409.
- `GET /jobs/{job_id}/investigation`, `/evidence`, `/reasoning`, `/graph` —
  structured query access to the pipeline's intermediate artifacts, not just
  the final rendered report. Each route reuses its owning backend package's
  own canonical serializer (`InvestigationSerializer`, `EvidenceSerializer`,
  `ReasoningSerializer`, `GraphSerializer`) — `Serializer.serialize(obj)` →
  `json.loads` → a typed Pydantic response model — so the JSON returned here
  is byte-identical to what that package already deterministically produces;
  nothing is re-implemented. `/evidence` is filtered to the requesting job's
  own records (see "Evidence scoping" below). `/graph` accepts `node_types`
  (comma-separated `GraphNodeKind` values) and `limit` (caps node count,
  after id-sorting); `depth` is accepted and validated but a documented
  no-op — there is no seed-node parameter to expand from in this route, and
  `reveng_knowledge_graph` has no traversal primitive.

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
records a `PENDING` job under a lock, and hands the work to the pool. Each
job's thread body runs the orchestrator *outside* the lock (so jobs don't
serialize each other) and only takes the lock briefly to record state
transitions (`PENDING → RUNNING → {COMPLETED, FAILED, CANCELLED}`). Status/
result reads return snapshots (`dataclasses.replace`), never the live mutable
`Job`, so a polling client never observes a half-updated record. A failing
job's exception is caught at the job boundary and stored as a string — it
never escapes into the pool thread or leaks a raw traceback to a caller.
`JobHistoryStore` (an internal, non-exported helper) factors the newest-first
filter/paginate logic for `GET /jobs` out of `JobManager` itself.

`PipelineResult` (Phase 017) retains the `KnowledgeGraph`, `ReasoningResult`,
and `InvestigationCase` objects the orchestrator builds along the way — Phase
014 discarded them as local variables once the final `Report` was built. This
is what makes the `/investigation`, `/evidence`, `/reasoning`, and `/graph`
query routes possible: `Job.result` already carries everything they need, so
no separate cache was introduced.

### Phase progress via lifecycle events

`PipelineOrchestrator.run()` accepts an internal, non-public `on_event`
listener and emits `PhaseStarted`/`PhaseCompleted`/`ArtifactProduced`/
`PipelineFailure`/`PipelineCancelled` events at each of its six phase
boundaries (`producer → static_analysis → knowledge_graph → reasoning →
investigation → reporting`). `JobManager` subscribes to update
`Job.current_phase`/`Job.phases`/`Job.artifact_ref` in real time as a job
runs on its background thread — `artifact_ref` becomes known (and filterable
via `GET /jobs?artifact=`) as soon as the static-analysis phase completes,
long before the job finishes. These event types are implementation detail,
not re-exported from the package's `__all__`.

### Cooperative cancellation

`DELETE /jobs/{job_id}` on a `Running` job cannot forcibly kill its thread —
Python offers no such primitive, and this package deliberately doesn't fight
that. Instead it sets `Job.cancel_requested`, which `run()` checks via an
`on_event`-adjacent `cancellation_check` callback at the *next* phase
boundary: the currently-running phase always finishes cleanly first (the
"worker cleanup" step), then the boundary check observes the flag, raises an
internal `CancellationRequested`, and `JobManager` transitions the job to
`Cancelled` rather than treating it as a failure. A `Pending` job (still
queued, not yet started) is cancelled immediately with no such wait.

### Evidence scoping

One `EvidenceRepository` instance is shared across every job's lifetime
(constructed once in `build_service()`) — evidence isn't stored per-job.
`GET /jobs/{job_id}/evidence` filters the shared repository's `enumerate()`
down to records whose `artifact_ref` matches this job's own, before wrapping
them in a `RepositorySnapshot` for `EvidenceSerializer`.

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
