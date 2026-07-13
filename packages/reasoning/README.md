# reveng-reasoning

**Owner:** Implementation Specification 005 — Reasoning
**Status:** Implemented (Engineering Phase 010)
**Layer:** Deterministic inference engine; builds on core-substrate, knowledge-graph, and storage-evidence.

The reasoning package is the platform's **deterministic inference engine**. It
consumes the `KnowledgeGraph` and the `EvidenceRepository` and derives new facts
through explicit rules, emitting immutable `Inference` objects. **This is not AI**:
no LLM, ML, embeddings, classifiers, probabilistic scoring, malware/threat
intelligence, heuristics, or pattern matching beyond explicit rules.

## Responsibilities

- **Rule model** — `Rule` contract + `RuleRegistry` (on the substrate
  `KeyedRegistry`), `ReasoningPlanner`, `RuleExecutor`, and `ReasoningEngine`.
- **Inference model** — immutable, content-derived `Inference` with a full
  `InferenceExplanation`.
- **Validation / serialization / query** — structural validation, canonical JSON,
  and exact-match queries.

## Explainability

Every `Inference` stores an `InferenceExplanation` recording the **rule applied**,
the **input evidence ids**, the **input graph node ids**, the **input graph edge
ids**, and the **output fact**. Nothing is hidden — every conclusion can be traced
back to the exact facts that produced it.

## Determinism

Same graph + evidence + rule set ⇒ identical conclusions. Inference identity is
`SHA256(rule_id | subject | fact | sorted-inputs)`; rules iterate in sorted order;
results are sorted by id and deduplicated. No timestamps, UUIDs, randomness,
scores, or probabilities.

## Immutable outputs

Reasoning never mutates the `KnowledgeGraph`, `Evidence`, or IR. It only emits
immutable `Inference` objects.

## Extension model

Register a custom rule with `ReasoningManager.register(...)` / `RuleRegistry`. The
built-in reference rules (unused function, dangling reference, duplicate symbol,
missing entry symbol, …) are the initial set only; the registry is authoritative
and open. Every rule is a pure, deterministic pattern matcher — a rule that matches
nothing returns zero inferences.

## Dependency rules

This package may import only `core-substrate`, `knowledge-graph`,
`storage-evidence`, and the four engineering libs. It must never import
static-analysis, pass-engine, domain-producers, another sibling package, or any
app. The two sibling edges (→ knowledge-graph, → storage) are explicitly
allowlisted in the repository dependency validator.

## Module naming

The `Rule` contract lives in `rules.py`; the built-in reference rules live in the
`reference/` subpackage (Python cannot have both a `rules.py` module and a `rules/`
package in one directory).
