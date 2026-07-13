# reveng-knowledge-graph

**Owner:** Implementation Specification 007 — Knowledge Graph
**Status:** Implemented (Engineering Phase 009)
**Layer:** Canonical semantic graph; builds on core-substrate, intermediate-representation, and storage-evidence.

The knowledge graph package is the platform's canonical **semantic graph**. It
consumes canonical IR and Evidence and constructs a deterministic, immutable graph
of nodes, edges, and properties. It records facts and relationships only — it
performs **no** reasoning, inference, scoring, ranking, graph algorithms, malware
detection, persistence, or AI.

## Responsibilities

- **Graph model** — immutable `GraphNode`, `GraphEdge`, and `PropertyBag`.
- **Builder pipeline** — `KnowledgeGraphBuilder` is the only construction path; it
  consumes an `IRModule` and a tuple of `Evidence` and produces a validated
  `KnowledgeGraph`.
- **Validation / indexing / query / serialization** — structural validation,
  deterministic indexes, exact-match queries, and canonical JSON.

## Graph model

- **Node kinds:** Module, Function, Symbol, Section, String, Resource, Artifact,
  Evidence, Namespace.
- **Relationships:** CONTAINS, REFERENCES, IMPLEMENTS, IMPORTS, EXPORTS,
  DERIVED_FROM, GENERATED_BY, OBSERVED_IN. There are no inference relationships.

## Node kinds and relationships (builder mapping)

IR nodes map to graph nodes (Module→MODULE, Function/Method→FUNCTION,
Symbol/Import/Export/Class/Type→SYMBOL, Section/Segment→SECTION, String→STRING,
Data→RESOURCE, Namespace→NAMESPACE; basic-block/instruction are below the semantic
layer and skipped). Each `Evidence` becomes an EVIDENCE node; each distinct
`artifact_ref` becomes an ARTIFACT node. Edges: IR containment → CONTAINS;
module→IMPORTS/EXPORTS→symbol for import/export symbols; IR entity→OBSERVED_IN→
evidence from `evidence.ir_refs`; evidence→DERIVED_FROM→artifact from
`evidence.artifact_ref`.

## Determinism

`GraphNodeID = SHA256(kind | logical_key)` and
`GraphEdgeID = SHA256(source | relationship | target)`, where logical keys reuse
existing identities (`IRIdentifier`, `EvidenceID`, artifact content hash). Same IR
+ Evidence + config ⇒ identical node ids, edge ids, ordering, and serialization.
No timestamps, UUIDs, or randomness. The graph is immutable; an update produces a
new version.

## Dependency rules

This package may import only `core-substrate`, `intermediate-representation`,
`storage-evidence`, and the four engineering libs. It must never import
producers, pass-engine, static-analysis, another sibling package, or any app. The
two sibling edges (→ IR, → storage) are explicitly allowlisted in the repository
dependency validator.

_Note: the Phase 001 ownership reservation labeled this package "Implementation
Specification 006"; the Phase 009 brief specifies "Implementation Specification
007". The Engineering-Phase numbering differs from the canonical Implementation
Specification numbering by one; this document follows the phase brief._
