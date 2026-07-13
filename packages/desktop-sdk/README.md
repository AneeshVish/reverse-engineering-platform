# reveng-desktop-sdk

**Owner:** Engineering Phase 015 — Desktop Integration / IPC
**Status:** Implemented (Engineering Phase 015)
**Layer:** Desktop-facing integration library; typed client + local UI-adjacent state models over the public API service.

This package connects a desktop application to the Phase-014 public API
service (`reveng_public_api` / `apps/reveng-api`). It performs no analysis,
reasoning, investigation, reporting, or plugin execution of its own —
everything goes through the public API's REST endpoints.

## What it exposes

- `DesktopClient` — a typed, sync HTTP client over the six public-API
  routes: `upload()`, `submit_job()`, `job_status()`, `job_report()`,
  `plugins()`, `health()`, plus `poll_job()` (a bounded sleep-loop until a
  job reaches a terminal state).
- `HttpIPC` — the desktop IPC abstraction; pure delegation to
  `DesktopClient`, wrapping the `IPCProtocol` seam a later phase could
  implement over a different transport.
- `DesktopService` — service lifecycle: attaches to a reachable service, or
  (if configured) self-manages a local process; `ensure_connected()` is the
  "automatically reconnects" behavior.
- `Workspace`/`Project`/`DesktopSession`/`Preferences` — local, UI-adjacent
  state models (immutable `Project`, mutable in-memory-only `DesktopSession`,
  persisted `Workspace`/`Preferences`).
- `DesktopManager` — the composition root: `open_project()`,
  `close_project()`, `submit_artifact()`, `refresh_job()`, `fetch_report()`,
  `plugins()`, `health()`/`remote_health()`.

## Dependency rules

This package is permitted to import only `reveng_public_api` (plus
`reveng_core_substrate` and the four engineering libs). No domain-producers,
pass-engine, static-analysis, storage, knowledge-graph, reasoning,
investigation, reporting, or plugin-sdk import is allowed — everything goes
through the public API's own orchestration. The reverse direction is closed:
nothing may import `reveng_desktop_sdk`. Enforced by the repository
dependency validator and `tests/engineering/test_dep_layering.py`.

## Why the GUI isn't touched this phase

The existing desktop application is the legacy PyQt6 GUI at repo-root
`src/gui/main_window.py` (launched by repo-root `main.py`). Today it performs
every analysis action as an in-process call into `src/core/*` (disassembler,
Ghidra/RetDec, Ollama, external threat-intel APIs) with zero HTTP calls to
any local backend — and its panels display raw disassembly/decompiled
C/CFGs, which have no equivalent in the new pipeline's `Report` (findings/
sections) shape. There is no coherent "replace this call with that call"
mapping today. This phase deliberately does not edit `src/`, `main.py`, or
add runtime code to `apps/reveng-desktop` — it delivers a complete, fully
tested, standalone integration library and proves it end-to-end via its own
test suite plus a manual smoke test. Wiring specific legacy buttons to it is
deferred to the dedicated UI/UX modernization phase, once there's a concrete
design for how `Report`/`Job`/`Plugin` shapes relate to the existing panels.

## Service lifecycle

`DesktopService.start()` always attempts to attach to whatever is reachable
at the configured `base_url` first. If nothing answers and
`self_manage_process` is enabled, it spawns a local process running
`reveng_api.app` under `uvicorn` via a subprocess command string (not
`python -m reveng_api`, since that entrypoint hardcodes `host="0.0.0.0",
port=8000` with no override — editing it was out of scope for this phase),
and polls `/health` with a bounded timeout. This subprocess launch never
creates an `import reveng_api` edge in this package's own source — the
command is a string evaluated by a separate OS process, invisible to
`check_dep_001`'s AST scan of this package's imports.
