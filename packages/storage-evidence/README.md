# reveng-storage-evidence

**Owner:** Implementation Specification 005 — Storage / Evidence
**Status:** Implemented (Engineering Phase 007)
**Layer:** Canonical in-memory evidence store; builds on `core-substrate` and `intermediate-representation`.

The storage / evidence package is the platform's canonical **in-memory** evidence
store. It owns storage contracts, versioned repositories, immutable evidence
records, indexing, exact-match querying, snapshots, and synchronous transactions.
It performs **no** reverse engineering, **no** persistence (no SQLite/PostgreSQL/
filesystem database), no graph construction, and no reasoning. Everything is
deterministic, synchronous, and memory-resident.

## Repository model

`EvidenceRepository` is a versioned, lock-guarded in-memory store:

- `add` inserts a new logical evidence record (duplicate id rejected).
- `replace` supersedes the current version, appending a new version marked
  `Active` (the prior version becomes `Superseded`).
- `lookup` returns the latest version; `history` returns all versions.
- `enumerate` returns the latest version of every record in deterministic id
  order.
- `remove` drops all versions of a logical id.

## Evidence lifecycle

`Evidence` records are immutable frozen values. An update never mutates a record;
it creates a new version. Identity (`EvidenceID`) is a SHA-256 of a caller-
supplied stable logical key — no UUIDs, timestamps, or randomness. State
progresses `Draft → Active → Superseded → Retracted`. Confidence uses the frozen
five-tier model (OBSERVED, MEASURED, EXTRACTED, INFERRED, UNKNOWN) with no implied
order. A record's `payload` is **opaque** to storage — recorded and returned
unchanged, never interpreted.

## Indexing

`IdentityIndex`, `KindIndex`, `ArtifactIndex` (by artifact reference string), and
`IRIndex` (by referenced `IRIdentifier`) are deterministic, rebuildable dict-backed
exact-lookup indexes. No search algorithms.

## Snapshots & transactions

`RepositorySnapshot` / `SnapshotBuilder` capture immutable, id-ordered repository
state for reproducible reads. `Transaction` stages add/replace/remove operations
and applies them atomically on `commit` (all-or-nothing under the repository lock);
`rollback` discards staged operations. Transactions do not nest.

## Serialization

`EvidenceSerializer` / `EvidenceDeserializer` produce canonical, order-independent
JSON with round-trip equality. Payloads must be JSON-encodable; otherwise a
`SerializationError` is raised.

## Dependency rules

This package may import only `reveng-core-substrate`,
`reveng-intermediate-representation`, and the four engineering libs. It must never
import `domain-producers`, `pass-engine`, another sibling package, or any app. The
`storage-evidence → intermediate-representation` edge is explicitly allowlisted in
the repository dependency validator.

_Note: the Phase 001 ownership reservation labeled this package "Implementation
Specification 004"; the Phase 007 brief specifies "Implementation Specification
005". The two numbering schemes differ by one; this document follows the phase
brief._
