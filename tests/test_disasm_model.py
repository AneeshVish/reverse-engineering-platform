"""Virtual disassembly model tests."""

from src.core.program_model import ProgramModel
from src.gui.models.disasm_model import VirtualDisasmModel


def test_virtual_disasm_model_row_count():
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, rbx"},
        {"address": 0x1003, "mnemonic": "ret", "op_str": ""},
    ]
    model = ProgramModel(instructions=instructions)
    vm = VirtualDisasmModel()
    vm.set_program_model(model)
    assert vm.rowCount() == 2
    assert "1000" in vm.data(vm.index(0, 0))


def test_find_address_row():
    vm = VirtualDisasmModel()
    vm.set_lines(["00001000: mov rax, rbx", "00001003: ret"])
    assert vm.find_address_row(0x1000) == 0
