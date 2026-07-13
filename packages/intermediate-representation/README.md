# reveng-intermediate-representation

**Owner:** Implementation Specification 004 — Canonical IR
**Status:** Implemented (Engineering Phase 006)
**Layer:** Shared representation; builds on `core-substrate`.

The intermediate representation is the platform's **canonical program model** —
the immutable language every later reverse-engineering capability speaks. It owns
only the data model and construction APIs. It performs **no analysis**: it never
parses binaries, disassembles, resolves symbols, reasons, or stores anything.

## Responsibilities

- **Immutable model** — nodes (`ModuleNode` … `ExportNode`), relationships
  (`IREdge`), `Instruction`/`Operand`, the `IRType` hierarchy, `Symbol`, and
  `MetadataBag`. Every public object is a frozen, immutable value.
- **Deterministic identity** — `IRIdentifier` is a SHA-256 derived from an
  entity's kind, hierarchical `IRPath`, and local content. No UUIDs, timestamps,
  or randomness. Equivalent structures get identical identifiers, so different
  producers of equivalent artifacts generate identical IR (canonical form).
- **Builders** — `IRBuilder` / `ModuleBuilder` / `FunctionBuilder` /
  `InstructionBuilder` are the **only** construction path. They compute
  identities, emit `Contains` edges, and validate before returning an
  `IRModule`.
- **Structural validation** — duplicate IDs, dangling edge endpoints, invalid
  parent references, missing required fields, and forbidden containment cycles.
  No semantic validation.
- **Canonical serialization** — `IRSerializer` / `IRDeserializer` produce stable,
  order-independent JSON with no persistence backend. The same module always
  serializes to identical bytes; a round-trip reproduces an equal module.

## Immutability

There is no mutable graph and no in-place editing. Nodes reference each other
only by identifier (via edges), never by object reference. A transformation
always returns a new `IRModule`.

## Identifiers

Identity derives solely from content and parent hierarchy:
`IRIdentifier = SHA-256(kind ‖ path ‖ content)`. Because it excludes producer
identity and any nondeterministic input, IR is reproducible and comparable across
runs and producers.

## Public interfaces

The public API is everything exported from
`reveng_intermediate_representation.__init__` (`__all__`). It is the frozen Phase
006 surface; later phases extend it additively only.

## Dependency rules

This package may import only `reveng-core-substrate` and the four engineering
libs (`reveng-types`, `reveng-errors`, `reveng-config`, `reveng-logging`). It is
intentionally decoupled from the ingestion layer — it does not import
`domain-producers` — and must never import another sibling package or any app.
