"""Smoke tests for the Capstone disassembler wrapper."""

import pytest

from src.core.disassembler import DisassemblerEngine, Architecture


def test_x86_64_disassembles_simple_bytes():
    dis = DisassemblerEngine()
    assert dis.initialize(Architecture.X86_64) is True
    # mov eax, 1 ; ret
    code = b"\xb8\x01\x00\x00\x00\xc3"
    ins = dis.disassemble(code, 0x1000)
    mnemonics = [i["mnemonic"] for i in ins]
    assert "mov" in mnemonics
    assert "ret" in mnemonics


@pytest.mark.parametrize("arch", [Architecture.X86, Architecture.ARM, Architecture.ARM64])
def test_all_architectures_initialize(arch):
    dis = DisassemblerEngine()
    assert dis.initialize(arch) is True


def test_uninitialized_returns_empty():
    dis = DisassemblerEngine()
    assert dis.disassemble(b"\x90", 0) == []
