# reveng-static-analysis

**Owner:** Implementation Specification 006 — Static Analysis
**Status:** Implemented (Engineering Phase 008)
**Layer:** First reverse-engineering capability; builds on core-substrate, domain-producers, pass-engine, IR, and storage-evidence.

The static analysis package is the platform's first real reverse-engineering
capability. It consumes `Artifact`s, runs deterministic analyzers, produces
canonical IR, and emits Evidence. It performs **no** disassembly, decompilation,
CFG/call-graph recovery, malware detection, reasoning, graph construction,
persistence, or AI. Framework-first: the machinery is real; ISA-specific parsing
is placeholder.

## Responsibilities

- **Analyzer framework** — `Analyzer` contract + `AnalyzerRegistry` (on the
  substrate `KeyedRegistry`), `AnalysisPlanner`, `AnalysisExecutor`, and
  `AnalysisPipeline`.
- **IR generation** — `IRArtifactBuilder` turns aggregated extraction into a
  canonical `IRModule` via the IR builders.
- **Evidence emission** — `EvidenceBuilder` turns extraction + IR into
  deterministic `Evidence` records via `reveng_storage_evidence.build_evidence`,
  optionally emitting into an in-memory `StorageManager`.

## Analyzer lifecycle

An `Analyzer` declares `AnalyzerMetadata` (identifier, version, capabilities,
applicable `ArtifactType`s, priority) and implements `analyze(context)`. State
progresses `Registered → Selected → Running → Completed | Failed`. Analyzers must
be pure and deterministic: identical context ⇒ identical extraction.

The planner selects analyzers applicable to the artifact type in a deterministic
order (descending priority, then registration order); the executor runs each
through a `guard` boundary so no raw exception escapes; the pipeline aggregates
extraction, builds IR, and emits Evidence into an `AnalysisReport`.

## Determinism

Same artifact + config + registered analyzers ⇒ byte-identical IR, Evidence, and
ordering. IR module names/ids derive from the artifact content hash; evidence keys
derive from `{content_hash}:{category}:{entity}`. No timestamps, UUIDs, randomness,
or machine-specific ordering.

## Architecture neutrality

The framework names x86/x64/ARM/ARM64/MIPS/PowerPC/RISC-V via `Architecture` but
embeds no ISA assumptions. Instruction, function, and reference modules are neutral
framework abstractions with no decoder or recovery algorithm.

## Extension model

Register a custom analyzer with `StaticAnalysisManager.register(...)` /
`AnalyzerRegistry`. Reference analyzers (`binary_header`, `strings`,
`section_table`, …) are the initial set only; the registry is authoritative and
open. Only `strings` reads raw content (a bounded, shallow ASCII scan); the
format-structural analyzers are honest placeholders pending real parsers.

## Dependency rules

This package may import `core-substrate`, `domain-producers`, `pass-engine`,
`intermediate-representation`, `storage-evidence`, and the four engineering libs —
nothing else. The four sibling edges are explicitly allowlisted in the repository
dependency validator.

_Note: the brief specifies `Owner: Implementation Specification 006`. The
Engineering-Phase numbering differs from the canonical Implementation
Specification numbering (canonically static analysis is Research 004 / the `static`
module of Implementation Specification 001); this document follows the phase brief._

## Module naming

Implementation Specification 006 lists both an `analyzers.py` module and an
`analyzers/` package; Python cannot have both in one directory, so the reference
analyzers live in the `reference/` subpackage while `analyzers.py` holds the
`Analyzer` contract.
