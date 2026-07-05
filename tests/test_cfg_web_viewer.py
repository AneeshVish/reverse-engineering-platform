"""CFG 3D viewer bridge tests."""

import json

from src.core.program_model import ProgramModel
from src.gui.cfg_web_viewer import GraphBridge


def test_graph_bridge_includes_tooltip_fields():
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, 1"},
        {"address": 0x1003, "mnemonic": "jmp", "op_str": "0x1010"},
        {"address": 0x1010, "mnemonic": "ret", "op_str": ""},
    ]
    model = ProgramModel(instructions=instructions)
    data = json.loads(GraphBridge(model).get_graph_data())
    assert len(data["nodes"]) >= 2
    attrs = data["nodes"][0]["attributes"]
    assert "address" in attrs
    assert "disassembly" in attrs
    assert "instruction_count" in attrs
    assert "successors" in attrs
