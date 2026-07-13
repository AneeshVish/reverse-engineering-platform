"""IR tests: builders are the construction path, with validation."""

from __future__ import annotations

import pytest
from _ir_helpers import build_sample_module
from reveng_intermediate_representation import (
    ConstructionError,
    FunctionSignature,
    Instruction,
    ModuleBuilder,
)


def test_build_produces_validated_module() -> None:
    module = build_sample_module()
    assert len(module.nodes) == 5
    assert len(module.edges) == 4


def test_empty_module_name_rejected() -> None:
    with pytest.raises(ConstructionError):
        ModuleBuilder("")


def test_empty_section_name_rejected() -> None:
    mb = ModuleBuilder("m")
    with pytest.raises(ConstructionError):
        mb.add_section("")


def test_empty_function_name_rejected() -> None:
    mb = ModuleBuilder("m")
    with pytest.raises(ConstructionError):
        mb.function_builder("", FunctionSignature(name=""))


def test_instruction_requires_mnemonic() -> None:
    mb = ModuleBuilder("m")
    fb = mb.function_builder("f")
    block = fb.add_basic_block("entry")
    ib = fb.instruction_builder(block, "entry")
    with pytest.raises(ConstructionError):
        ib.build(0, Instruction(mnemonic=""))


def test_deterministic_identities_across_builds() -> None:
    a = build_sample_module()
    b = build_sample_module()
    assert a.root == b.root
    assert {n.identifier for n in a.nodes} == {n.identifier for n in b.nodes}


def test_canonical_across_module_names() -> None:
    # Same structure, different module name → different root (name is identity).
    a = build_sample_module("libfoo")
    b = build_sample_module("libbar")
    assert a.root != b.root
