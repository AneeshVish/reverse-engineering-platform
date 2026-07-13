"""IR tests: deterministic serialization and round-trip."""

from __future__ import annotations

from _ir_helpers import build_sample_module
from reveng_intermediate_representation import (
    IRDeserializer,
    IRSerializer,
    NodeKind,
)


def _serialize(module) -> str:
    return IRSerializer().serialize(module)


def test_serialization_is_deterministic() -> None:
    a = build_sample_module()
    b = build_sample_module()
    assert _serialize(a) == _serialize(b)


def test_serialization_is_order_independent() -> None:
    # Reversing node order must not change canonical output.
    import dataclasses

    module = build_sample_module()
    reversed_nodes = dataclasses.replace(module, nodes=tuple(reversed(module.nodes)))
    assert _serialize(module) == _serialize(reversed_nodes)


def test_round_trip_reproduces_equal_module() -> None:
    module = build_sample_module()
    data = _serialize(module)
    restored = IRDeserializer().deserialize(data)
    assert _serialize(restored) == data


def test_round_trip_preserves_structure() -> None:
    module = build_sample_module()
    restored = IRDeserializer().deserialize(_serialize(module))
    assert restored.root == module.root
    assert len(restored.nodes) == len(module.nodes)
    assert len(restored.edges) == len(module.edges)
    instrs = restored.nodes_of_kind(NodeKind.INSTRUCTION)
    assert len(instrs) == 1


def test_round_trip_preserves_instruction_operands() -> None:
    from reveng_intermediate_representation import InstructionNode

    module = build_sample_module()
    restored = IRDeserializer().deserialize(_serialize(module))
    ins_nodes = [n for n in restored.nodes if isinstance(n, InstructionNode)]
    assert ins_nodes[0].instruction is not None
    assert ins_nodes[0].instruction.mnemonic == "mov"
    assert len(ins_nodes[0].instruction.operands) == 2


def test_no_timestamp_in_output() -> None:
    data = _serialize(build_sample_module())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data
