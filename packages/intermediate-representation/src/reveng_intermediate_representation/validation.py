"""Structural validation of an IR module.

Purely structural: duplicate identifiers, dangling edge endpoints, invalid parent
(``Contains``) references, missing required fields, and forbidden cycles in the
containment hierarchy. No semantic validation — the IR layer does not judge
whether a representation is *meaningful*, only whether it is *well-formed*.
"""

from __future__ import annotations

from .edges import EdgeKind
from .errors import ValidationError
from .identity import IRIdentifier
from .nodes import IRModule

__all__ = ["validate_module", "IRValidator"]


def validate_module(module: IRModule) -> None:
    """Validate ``module`` structurally, raising ``ValidationError`` on failure."""

    ids: set[IRIdentifier] = set()
    for node in module.nodes:
        if not node.identifier.value:
            raise ValidationError("node has empty identifier", name=node.name)
        if not node.name:
            raise ValidationError("node missing required name", node=node.identifier.value)
        if node.identifier in ids:
            raise ValidationError("duplicate node identifier", node=node.identifier.value)
        ids.add(node.identifier)

    if module.root not in ids and module.nodes:
        raise ValidationError("root identifier is not a node", root=module.root.value)

    for edge in module.edges:
        if edge.source not in ids:
            raise ValidationError("edge source is not a node", source=edge.source.value)
        if edge.target not in ids:
            raise ValidationError("edge target is not a node", target=edge.target.value)

    _check_containment_acyclic(module)


def _check_containment_acyclic(module: IRModule) -> None:
    children: dict[IRIdentifier, list[IRIdentifier]] = {}
    for edge in module.edges:
        if edge.kind is EdgeKind.CONTAINS:
            children.setdefault(edge.source, []).append(edge.target)

    visiting: set[IRIdentifier] = set()
    done: set[IRIdentifier] = set()

    def visit(node_id: IRIdentifier) -> None:
        if node_id in done:
            return
        if node_id in visiting:
            raise ValidationError("containment cycle detected", node=node_id.value)
        visiting.add(node_id)
        for child in children.get(node_id, ()):
            visit(child)
        visiting.discard(node_id)
        done.add(node_id)

    for node_id in list(children):
        visit(node_id)


class IRValidator:
    """Object wrapper around :func:`validate_module`."""

    def validate(self, module: IRModule) -> None:
        validate_module(module)
