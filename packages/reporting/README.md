# reveng-reporting

**Owner:** Implementation Specification 008 — Reporting
**Status:** Implemented (Engineering Phase 012)
**Layer:** Deterministic reporting subsystem; builds on core-substrate, investigation, reasoning, knowledge-graph, and storage-evidence.

The reporting package is the platform's **deterministic reporting subsystem**. It
consumes immutable `InvestigationCase` objects (plus their referenced findings,
inferences, evidence, and graph entities) and produces deterministic, explainable
reports for analysts. It performs **no** analysis, reasoning, inference,
investigation, graph traversal, scoring, malware classification, AI, or
persistence — its only responsibility is transforming already-derived information
into structured reports.

## Report lifecycle

A `Report` is an immutable projection of an investigation case. Its identity is
`ReportID = SHA256(case_id | template | version)`. State progresses
`Draft → Final → Archived`; updates create new reports (nothing is mutated in
place). `ReportBuilder` is the only construction path.

## Templates

Templates are pure, deterministic section formatters. Five reference templates are
provided: `ExecutiveSummaryTemplate`, `TechnicalTemplate`, `EvidenceTemplate`,
`JSONTemplate`, and `MarkdownTemplate`. Each transforms a read-only
`RenderContext` (the case plus its reasoning, evidence, and graph inputs) into an
ordered tuple of `ReportSection`s whose `references` are upstream ids only.

## Rendering

`ReportRenderer` renders a report to JSON, Markdown, or HTML. Output is
byte-identical for identical reports. There is no PDF engine (that belongs to a
later phase).

## Determinism

Same investigation case + template ⇒ identical report, id, ordering, and
serialization. Sections are emitted in template order, references are sorted, and
there are no timestamps, UUIDs, or randomness.

## Explainability

Every report section references `FindingID` / `InferenceID` / `EvidenceID` /
graph ids only — nothing is summarized beyond deterministic formatting, and
validation confirms every reference resolves back to a real upstream id.

## Dependency rules

This package may import only `core-substrate`, `investigation`, `reasoning`,
`knowledge-graph`, `storage-evidence`, and the four engineering libs. It must never
import static-analysis, pass-engine, domain-producers, another sibling package, or
any app. The four sibling edges are explicitly allowlisted in the repository
dependency validator.

## Module naming

The concrete builder is `ReportBuilder` (in `builders.py`); the builder protocol
in `contracts.py` is named `ReportBuilderProtocol` to avoid a name clash within the
public namespace.
