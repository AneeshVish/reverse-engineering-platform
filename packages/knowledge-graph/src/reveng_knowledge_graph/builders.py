"""Canonical graph construction from IR and Evidence.

``KnowledgeGraphBuilder`` is the only construction path. It consumes a canonical
``IRModule`` and a tuple of ``Evidence`` and produces a validated, deterministic
``KnowledgeGraph``. It records facts only — it never infers, scores, or reasons.
IR and Evidence inputs are read-only.
"""

from __future__ import annotations

from reveng_intermediate_representation import (
    EdgeKind,
    IRModule,
    NodeKind,
    SymbolKind,
    SymbolNode,
)
from reveng_storage_evidence import Evidence

from .edges import GraphEdge, GraphEdgeID, RelationshipKind
from .nodes import GraphNode, GraphNodeID, GraphNodeKind
from .properties import PropertyBag
from .validation import validate_graph
from .graph import KnowledgeGraph

__all__ = ["KnowledgeGraphBuilder"]

# IR node kinds mapped into the semantic graph. Basic blocks and instructions are
# below the semantic layer and are intentionally not represented.
_NODE_KIND_MAP: dict[NodeKind, GraphNodeKind] = {
    NodeKind.MODULE: GraphNodeKind.MODULE,
    NodeKind.FUNCTION: GraphNodeKind.FUNCTION,
    NodeKind.METHOD: GraphNodeKind.FUNCTION,
    NodeKind.SYMBOL: GraphNodeKind.SYMBOL,
    NodeKind.IMPORT: GraphNodeKind.SYMBOL,
    NodeKind.EXPORT: GraphNodeKind.SYMBOL,
    NodeKind.CLASS: GraphNodeKind.SYMBOL,
    NodeKind.TYPE: GraphNodeKind.SYMBOL,
    NodeKind.SECTION: GraphNodeKind.SECTION,
    NodeKind.SEGMENT: GraphNodeKind.SECTION,
    NodeKind.STRING: GraphNodeKind.STRING,
    NodeKind.DATA: GraphNodeKind.RESOURCE,
    NodeKind.NAMESPACE: GraphNodeKind.NAMESPACE,
}


class KnowledgeGraphBuilder:
    """Builds a canonical knowledge graph from IR and evidence."""

    def build(self, ir_module: IRModule, evidence: tuple[Evidence, ...] = ()) -> KnowledgeGraph:
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        ir_to_graph: dict[str, GraphNodeID] = {}
        evidence_to_graph: dict[str, GraphNodeID] = {}
        artifact_to_graph: dict[str, GraphNodeID] = {}

        # 1. IR-derived nodes.
        for ir_node in ir_module.nodes:
            graph_kind = _NODE_KIND_MAP.get(ir_node.kind)
            if graph_kind is None:
                continue
            logical_key = ir_node.identifier.value
            node_id = GraphNodeID.of(graph_kind, logical_key)
            nodes[node_id.value] = GraphNode(
                id=node_id,
                kind=graph_kind,
                logical_key=logical_key,
                name=ir_node.name,
                properties=PropertyBag.of({"ir_kind": ir_node.kind.value}),
            )
            ir_to_graph[logical_key] = node_id

        # 2. Evidence nodes and artifact nodes.
        for record in evidence:
            ev_key = record.id.value
            ev_id = GraphNodeID.of(GraphNodeKind.EVIDENCE, ev_key)
            nodes[ev_id.value] = GraphNode(
                id=ev_id,
                kind=GraphNodeKind.EVIDENCE,
                logical_key=ev_key,
                name=record.kind.value,
                properties=PropertyBag.of(
                    {"evidence_kind": record.kind.value, "confidence": record.confidence.value}
                ),
            )
            evidence_to_graph[ev_key] = ev_id

            if record.artifact_ref and record.artifact_ref not in artifact_to_graph:
                art_id = GraphNodeID.of(GraphNodeKind.ARTIFACT, record.artifact_ref)
                nodes[art_id.value] = GraphNode(
                    id=art_id,
                    kind=GraphNodeKind.ARTIFACT,
                    logical_key=record.artifact_ref,
                    name=record.artifact_ref[:12],
                )
                artifact_to_graph[record.artifact_ref] = art_id

        # 3. CONTAINS edges from IR containment.
        for ir_edge in ir_module.edges:
            if ir_edge.kind is not EdgeKind.CONTAINS:
                continue
            src = ir_to_graph.get(ir_edge.source.value)
            tgt = ir_to_graph.get(ir_edge.target.value)
            if src is not None and tgt is not None:
                self._add_edge(edges, src, RelationshipKind.CONTAINS, tgt)

        # 4. IMPORTS / EXPORTS edges from the module to import/export symbols.
        module_id = ir_to_graph.get(ir_module.root.value)
        if module_id is not None:
            for ir_node in ir_module.nodes:
                relationship = self._import_export_relationship(ir_node)
                if relationship is None:
                    continue
                sym_id = ir_to_graph.get(ir_node.identifier.value)
                if sym_id is not None:
                    self._add_edge(edges, module_id, relationship, sym_id)

        # 5. OBSERVED_IN (IR entity -> evidence) and DERIVED_FROM (evidence -> artifact).
        for record in evidence:
            ev_id = evidence_to_graph[record.id.value]
            for ref in record.ir_refs:
                ir_graph_id = ir_to_graph.get(ref.value)
                if ir_graph_id is not None:
                    self._add_edge(edges, ir_graph_id, RelationshipKind.OBSERVED_IN, ev_id)
            if record.artifact_ref:
                art_id = artifact_to_graph.get(record.artifact_ref)
                if art_id is not None:
                    self._add_edge(edges, ev_id, RelationshipKind.DERIVED_FROM, art_id)

        graph = KnowledgeGraph(
            nodes=tuple(sorted(nodes.values(), key=lambda n: n.id.value)),
            edges=tuple(sorted(edges.values(), key=lambda e: e.id.value)),
            version=1,
        )
        validate_graph(graph)
        return graph

    @staticmethod
    def _import_export_relationship(ir_node: object) -> RelationshipKind | None:
        kind = getattr(ir_node, "kind", None)
        if kind is NodeKind.IMPORT:
            return RelationshipKind.IMPORTS
        if kind is NodeKind.EXPORT:
            return RelationshipKind.EXPORTS
        if isinstance(ir_node, SymbolNode) and ir_node.symbol is not None:
            if ir_node.symbol.kind is SymbolKind.IMPORT:
                return RelationshipKind.IMPORTS
            if ir_node.symbol.kind is SymbolKind.EXPORT:
                return RelationshipKind.EXPORTS
        return None

    @staticmethod
    def _add_edge(
        edges: dict[str, GraphEdge],
        source: GraphNodeID,
        relationship: RelationshipKind,
        target: GraphNodeID,
    ) -> None:
        edge_id = GraphEdgeID.of(source, relationship, target)
        edges[edge_id.value] = GraphEdge(
            id=edge_id, relationship=relationship, source=source, target=target
        )
