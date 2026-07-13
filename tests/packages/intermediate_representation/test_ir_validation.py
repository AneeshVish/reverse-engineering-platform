"""IR tests: structural validation failures."""

from __future__ import annotations

import pytest
from _ir_helpers import build_sample_module
from reveng_intermediate_representation import (
    EdgeKind,
    FunctionNode,
    IREdge,
    IRIdentifier,
    IRModule,
    IRPath,
    ValidationError,
    derive_identifier,
    validate_module,
)


def _func(name: str) -> FunctionNode:
    path = IRPath.root().child(name)
    return FunctionNode(
        identifier=derive_identifier("function", path, name),
        name=name,
        path=path,
    )


def test_valid_module_passes() -> None:
    validate_module(build_sample_module())  # no raise


def test_duplicate_identifier_rejected() -> None:
    node = _func("f")
    module = IRModule(root=node.identifier, nodes=(node, node))
    with pytest.raises(ValidationError):
        validate_module(module)


def test_dangling_edge_endpoint_rejected() -> None:
    node = _func("f")
    ghost = IRIdentifier("0" * 64)
    module = IRModule(
        root=node.identifier,
        nodes=(node,),
        edges=(IREdge(kind=EdgeKind.CALLS, source=node.identifier, target=ghost),),
    )
    with pytest.raises(ValidationError):
        validate_module(module)


def test_missing_name_rejected() -> None:
    path = IRPath.root().child("x")
    node = FunctionNode(identifier=derive_identifier("function", path), name="", path=path)
    module = IRModule(root=node.identifier, nodes=(node,))
    with pytest.raises(ValidationError):
        validate_module(module)


def test_root_not_a_node_rejected() -> None:
    node = _func("f")
    module = IRModule(root=IRIdentifier("f" * 64), nodes=(node,))
    with pytest.raises(ValidationError):
        validate_module(module)


def test_containment_cycle_rejected() -> None:
    a, b = _func("a"), _func("b")
    module = IRModule(
        root=a.identifier,
        nodes=(a, b),
        edges=(
            IREdge(kind=EdgeKind.CONTAINS, source=a.identifier, target=b.identifier),
            IREdge(kind=EdgeKind.CONTAINS, source=b.identifier, target=a.identifier),
        ),
    )
    with pytest.raises(ValidationError):
        validate_module(module)
