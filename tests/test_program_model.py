"""Tests for the structured program model (basic blocks + CFG edges)."""

from src.core.program_model import ProgramModel, classify, branch_target


def _sample():
    # A small x86-like routine with a conditional and an unconditional branch.
    return [
        {"address": 0,  "mnemonic": "mov", "op_str": "eax, 1", "size": 5},
        {"address": 5,  "mnemonic": "cmp", "op_str": "eax, 0", "size": 3},
        {"address": 8,  "mnemonic": "je",  "op_str": "0x10",   "size": 2},  # -> 16, fall 10
        {"address": 10, "mnemonic": "mov", "op_str": "eax, 2", "size": 5},
        {"address": 15, "mnemonic": "jmp", "op_str": "0x0",    "size": 2},  # -> 0 (back edge)
        {"address": 16, "mnemonic": "ret", "op_str": "",       "size": 1},
    ]


def test_classify():
    assert classify("je") == "cond"
    assert classify("jmp") == "uncond"
    assert classify("call") == "call"
    assert classify("ret") == "ret"
    assert classify("mov") == "other"
    # ARM
    assert classify("beq") == "cond"
    assert classify("b.eq") == "cond"
    assert classify("bl") == "call"
    assert classify("b") == "uncond"
    assert classify("bic") == "other"   # data op, not a branch


def test_branch_target():
    assert branch_target("0x401000") == 0x401000
    assert branch_target("#0x1000") == 0x1000
    assert branch_target("rax") is None
    assert branch_target("") is None


def test_basic_block_splitting():
    m = ProgramModel(instructions=_sample())
    blocks = m.basic_blocks()
    assert [b.start for b in blocks] == [0, 10, 16]
    a, b, c = blocks
    assert a.successors == [16, 10]   # taken target then fall-through
    assert b.successors == [0]        # unconditional back edge
    assert c.successors == []         # ret has no successor


def test_build_cfg_edges():
    m = ProgramModel(instructions=_sample())
    g = m.build_cfg()
    assert set(g.nodes) == {0, 10, 16}
    assert set(g.edges) == {(0, 16), (0, 10), (10, 0)}


def test_stats_and_assembly_text():
    m = ProgramModel(instructions=_sample())
    s = m.stats()
    assert s["instructions"] == 6
    assert s["basic_blocks"] == 3
    assert s["edges"] == 3
    assert "je 0x10" in m.assembly_text()


def test_empty_model():
    m = ProgramModel(instructions=[])
    assert m.basic_blocks() == []
    assert m.stats()["basic_blocks"] == 0
