"""Built-in reference rules.

Ten deterministic, explainable structural rules over the knowledge graph and
evidence. They match explicit patterns only — no ML, heuristics, scoring, or
malware intelligence. A rule that matches nothing returns zero inferences. The
registry is authoritative and open to third-party rules.
"""

from __future__ import annotations

from reveng_knowledge_graph import GraphNodeKind, RelationshipKind

from ..config import ReasoningConfig
from ..inference import InferenceKind, build_inference
from ..registry import RuleRegistry
from ..rules import RuleContext, RuleRequirement, RuleResult
from .base import ReferenceRule, incoming, node_name, outgoing

__all__ = [
    "ReferenceRule",
    "UnusedFunctionRule",
    "ImportedButNotReferencedRule",
    "DeadSectionRule",
    "DuplicateSymbolRule",
    "OrphanNamespaceRule",
    "DanglingReferenceRule",
    "UnresolvedImportRule",
    "DuplicateEvidenceRule",
    "MultipleDefinitionsRule",
    "MissingEntrySymbolRule",
    "REFERENCE_RULE_TYPES",
    "register_builtin_rules",
]


class UnusedFunctionRule(ReferenceRule):
    identifier_ = "unused_function"
    inference_kind_ = InferenceKind.STRUCTURAL
    description_ = "a function with no incoming reference"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.FUNCTION,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for node in graph.nodes_of_kind(GraphNodeKind.FUNCTION):
            if not incoming(graph, node.id, RelationshipKind.REFERENCES):
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=node.id.value,
                        fact=f"unused function: {node_name(node)}",
                        input_nodes=(node.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class ImportedButNotReferencedRule(ReferenceRule):
    identifier_ = "imported_but_not_referenced"
    inference_kind_ = InferenceKind.REFERENCE
    description_ = "an imported symbol that is never referenced"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.SYMBOL,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for edge in graph.edges_of_kind(RelationshipKind.IMPORTS):
            target = graph.node_by_id(edge.target)
            if target is None:
                continue
            referenced = incoming(graph, target.id, RelationshipKind.REFERENCES) or outgoing(
                graph, target.id, RelationshipKind.REFERENCES
            )
            if not referenced:
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=target.id.value,
                        fact=f"imported but not referenced: {node_name(target)}",
                        input_nodes=(target.id.value,),
                        input_edges=(edge.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class DeadSectionRule(ReferenceRule):
    identifier_ = "dead_section"
    inference_kind_ = InferenceKind.STRUCTURAL
    description_ = "a section that contains nothing"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.SECTION,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for node in graph.nodes_of_kind(GraphNodeKind.SECTION):
            if not outgoing(graph, node.id, RelationshipKind.CONTAINS):
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=node.id.value,
                        fact=f"dead section (empty): {node_name(node)}",
                        input_nodes=(node.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class DuplicateSymbolRule(ReferenceRule):
    identifier_ = "duplicate_symbol"
    inference_kind_ = InferenceKind.DUPLICATION
    description_ = "two or more symbols share a name"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.SYMBOL,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        groups: dict[str, list[str]] = {}
        for node in graph.nodes_of_kind(GraphNodeKind.SYMBOL):
            groups.setdefault(node.name, []).append(node.id.value)
        inferences = []
        for name, ids in sorted(groups.items()):
            if len(ids) > 1:
                ids_sorted = tuple(sorted(ids))
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=ids_sorted[0],
                        fact=f"duplicate symbol: {name}",
                        input_nodes=ids_sorted,
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class OrphanNamespaceRule(ReferenceRule):
    identifier_ = "orphan_namespace"
    inference_kind_ = InferenceKind.STRUCTURAL
    description_ = "a namespace that contains nothing"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.NAMESPACE,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for node in graph.nodes_of_kind(GraphNodeKind.NAMESPACE):
            if not outgoing(graph, node.id, RelationshipKind.CONTAINS):
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=node.id.value,
                        fact=f"orphan namespace: {node_name(node)}",
                        input_nodes=(node.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class DanglingReferenceRule(ReferenceRule):
    identifier_ = "dangling_reference"
    inference_kind_ = InferenceKind.REFERENCE
    description_ = "a reference to a target that is not defined anywhere"

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for edge in graph.edges_of_kind(RelationshipKind.REFERENCES):
            target = graph.node_by_id(edge.target)
            if target is None:
                continue
            if not incoming(graph, target.id, RelationshipKind.CONTAINS):
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=target.id.value,
                        fact=f"dangling reference to: {node_name(target)}",
                        input_nodes=(target.id.value,),
                        input_edges=(edge.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class UnresolvedImportRule(ReferenceRule):
    identifier_ = "unresolved_import"
    inference_kind_ = InferenceKind.REFERENCE
    description_ = "an import with no matching export or local definition"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.SYMBOL,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for edge in graph.edges_of_kind(RelationshipKind.IMPORTS):
            target = graph.node_by_id(edge.target)
            if target is None:
                continue
            exported = incoming(graph, target.id, RelationshipKind.EXPORTS)
            contained = incoming(graph, target.id, RelationshipKind.CONTAINS)
            if not exported and not contained:
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=target.id.value,
                        fact=f"unresolved import: {node_name(target)}",
                        input_nodes=(target.id.value,),
                        input_edges=(edge.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class DuplicateEvidenceRule(ReferenceRule):
    identifier_ = "duplicate_evidence"
    inference_kind_ = InferenceKind.PROVENANCE
    description_ = "two or more evidence records assert the same fact"

    def apply(self, context: RuleContext) -> RuleResult:
        groups: dict[tuple[str, str, str], list[str]] = {}
        for record in context.evidence.enumerate():
            key = (
                record.kind.value,
                ",".join(sorted(r.value for r in record.ir_refs)),
                record.artifact_ref,
            )
            groups.setdefault(key, []).append(record.id.value)
        inferences = []
        for key, ids in sorted(groups.items()):
            if len(ids) > 1:
                ids_sorted = tuple(sorted(ids))
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=ids_sorted[0],
                        fact=f"duplicate evidence for: {key[0]}",
                        input_evidence=ids_sorted,
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class MultipleDefinitionsRule(ReferenceRule):
    identifier_ = "multiple_definitions"
    inference_kind_ = InferenceKind.DUPLICATION
    description_ = "a symbol name is defined under more than one container"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.SYMBOL,))

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        # name -> (parent ids, symbol ids, containment edge ids)
        by_name: dict[str, tuple[set[str], set[str], set[str]]] = {}
        for node in graph.nodes_of_kind(GraphNodeKind.SYMBOL):
            parents, syms, edge_ids = by_name.setdefault(node.name, (set(), set(), set()))
            for edge in incoming(graph, node.id, RelationshipKind.CONTAINS):
                parents.add(edge.source.value)
                syms.add(node.id.value)
                edge_ids.add(edge.id.value)
        inferences = []
        for name, (parents, syms, edge_ids) in sorted(by_name.items()):
            if len(parents) > 1:
                sym_ids = tuple(sorted(syms))
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=sym_ids[0],
                        fact=f"multiple definitions of: {name}",
                        input_nodes=sym_ids,
                        input_edges=tuple(sorted(edge_ids)),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


class MissingEntrySymbolRule(ReferenceRule):
    identifier_ = "missing_entry_symbol"
    inference_kind_ = InferenceKind.COMPLETENESS
    description_ = "a module with no entry-named symbol and no exports"
    requirement_ = RuleRequirement(node_kinds=(GraphNodeKind.MODULE,))

    def __init__(self, entry_symbols: tuple[str, ...] = ("main", "_start", "start")) -> None:
        self._entry = frozenset(entry_symbols)

    def apply(self, context: RuleContext) -> RuleResult:
        graph = context.graph
        inferences = []
        for module in graph.nodes_of_kind(GraphNodeKind.MODULE):
            contained_names = {
                child.name
                for edge in outgoing(graph, module.id, RelationshipKind.CONTAINS)
                if (child := graph.node_by_id(edge.target)) is not None
            }
            has_entry = bool(contained_names & self._entry)
            has_exports = bool(outgoing(graph, module.id, RelationshipKind.EXPORTS))
            if not has_entry and not has_exports:
                inferences.append(
                    build_inference(
                        rule_id=self.identifier_,
                        kind=self.inference_kind_,
                        subject=module.id.value,
                        fact=f"missing entry symbol: {node_name(module)}",
                        input_nodes=(module.id.value,),
                    )
                )
        return RuleResult(self.identifier_, tuple(inferences))


REFERENCE_RULE_TYPES: tuple[type[ReferenceRule], ...] = (
    UnusedFunctionRule,
    ImportedButNotReferencedRule,
    DeadSectionRule,
    DuplicateSymbolRule,
    OrphanNamespaceRule,
    DanglingReferenceRule,
    UnresolvedImportRule,
    DuplicateEvidenceRule,
    MultipleDefinitionsRule,
    MissingEntrySymbolRule,
)


def register_builtin_rules(
    registry: RuleRegistry, config: ReasoningConfig | None = None
) -> None:
    """Register the ten reference rules into ``registry``."""

    entry = config.entry_symbols() if config is not None else ("main", "_start", "start")
    for cls in REFERENCE_RULE_TYPES:
        rule = MissingEntrySymbolRule(entry) if cls is MissingEntrySymbolRule else cls()
        registry.register(rule)
