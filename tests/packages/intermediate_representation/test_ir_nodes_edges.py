"""IR tests: node and edge creation and immutability."""

from __future__ import annotations

import dataclasses

import pytest
from _ir_helpers import build_sample_module
from reveng_intermediate_representation import (
    EdgeKind,
    FunctionNode,
    IRPath,
    ModuleNode,
    NodeKind,
    derive_identifier,
)


def test_module_contains_expected_node_kinds() -> None:
    module = build_sample_module()
    kinds = {n.kind for n in module.nodes}
    assert NodeKind.MODULE in kinds
    assert NodeKind.SECTION in kinds
    assert NodeKind.FUNCTION in kinds
    assert NodeKind.BASIC_BLOCK in kinds
    assert NodeKind.INSTRUCTION in kinds


def test_root_is_module_node() -> None:
    module = build_sample_module()
    root = module.node_by_id(module.root)
    assert isinstance(root, ModuleNode)
    assert root.architecture == "x86_64"


def test_contains_edges_link_parent_child() -> None:
    module = build_sample_module()
    contains = module.edges_of_kind(EdgeKind.CONTAINS)
    # Module → section, module → function, function → block, block → instruction
    assert len(contains) == 4
    ids = module.node_ids()
    for edge in contains:
        assert edge.source in ids
        assert edge.target in ids


def test_nodes_are_immutable() -> None:
    node = FunctionNode(
        identifier=derive_identifier("function", IRPath.root().child("f")),
        name="f",
        path=IRPath.root().child("f"),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        node.name = "g"  # type: ignore[misc]


def test_nodes_of_kind_query() -> None:
    module = build_sample_module()
    funcs = module.nodes_of_kind(NodeKind.FUNCTION)
    assert len(funcs) == 1
    assert funcs[0].name == "main"
