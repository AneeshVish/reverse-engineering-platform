# reveng-investigation

**Owner:** Implementation Specification 007 — Investigation
**Status:** Implemented (Engineering Phase 011)
**Layer:** Analyst case-construction layer; builds on core-substrate, reasoning, knowledge-graph, and storage-evidence.

The investigation package is the platform's **case-construction layer**. It
consumes immutable `Inference` objects, the `KnowledgeGraph`, and the
`EvidenceRepository` and groups them into deterministic investigation cases,
findings, timelines, and evidence chains suitable for analysts. It performs **no
new reasoning**, creates **no** inferences, and mutates nothing upstream — it is
purely an organization layer.

## Responsibilities

- **Case & finding model** — immutable `InvestigationCase`, `Finding`,
  `FindingExplanation`, `Timeline`, and evidence/graph/inference `chains`.
- **Builder pipeline** — `InvestigationBuilder` is the only construction path; the
  reference investigations group existing inferences into findings.
- **Validation / indexing / query / serialization** — structural validation,
  deterministic indexes, exact-match queries, and canonical JSON.

## Explainability

Every `Finding` stores a `FindingExplanation` recording the contributing
**inference ids**, **evidence ids**, **graph node ids**, and **graph edge ids** —
so every finding is fully traceable to the inference, evidence, and graph elements
that produced it.

## Determinism

Same graph + evidence + inferences ⇒ an identical investigation. `FindingID =
SHA256(kind | subject | sorted inference ids)` and `CaseID = SHA256(sorted
inference ids)`. Findings are id-sorted; the timeline is ordered from the
contributing `InferenceID` values, not wall-clock time. No timestamps, UUIDs, or
randomness.

## Reference investigations

Eight deterministic investigations group existing inferences into findings: Dead
Code, Unused Function, Duplicate Symbol, Missing Entry, Unresolved Import,
Duplicate Evidence, Namespace Integrity, and Reference Integrity. Each merely
selects the inferences produced by specific reasoning rules — no malware logic, no
AI, no new reasoning.

## Dependency rules

This package may import only `core-substrate`, `reasoning`, `knowledge-graph`,
`storage-evidence`, and the four engineering libs. It must never import
static-analysis, pass-engine, domain-producers, another sibling package, or any
app. The three sibling edges (→ reasoning, → knowledge-graph, → storage) are
explicitly allowlisted in the repository dependency validator.
