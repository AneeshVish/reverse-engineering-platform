"""Unicorn stack-string recovery — emulate stack-relative writes."""

import struct
from typing import List, Optional

UNICORN = False
UC_X86_REG_RSP = 0
UC_X86_REG_RBP = 0

try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE,
        UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    )
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP
    UNICORN = True
except ImportError:
    Uc = None  # type: ignore

STACK_ADDR = 0x90000
STACK_SIZE = 1024 * 1024


class StackStringExtractor:
    """Emulate a code slice and capture stack writes."""

    def __init__(self, code_bytes: bytes, base_addr: int = 0x1000):
        self.code_bytes = code_bytes
        self.base_addr = base_addr
        self.extracted_data = bytearray()

    def _mem_write_hook(self, uc, access, address, size, value, user_data):
        if STACK_ADDR <= address < STACK_ADDR + STACK_SIZE:
            val_bytes = struct.pack("<Q", value & ((1 << (size * 8)) - 1))[:size]
            self.extracted_data.extend(val_bytes)

    def run_emulation(self, start_addr: Optional[int] = None) -> bytes:
        if not UNICORN:
            return b""
        start = start_addr if start_addr is not None else self.base_addr
        self.extracted_data = bytearray()
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        code_size = max(len(self.code_bytes), 4096)
        uc.mem_map(start, code_size, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(start, self.code_bytes)
        uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 8)
        uc.reg_write(UC_X86_REG_RBP, STACK_ADDR + STACK_SIZE - 8)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_write_hook)
        try:
            uc.emu_start(start, start + len(self.code_bytes), timeout=0, count=500)
        except Exception:
            pass
        return bytes(self.extracted_data)


def extract_stack_strings(code_bytes: bytes, base_addr: int = 0x1000) -> str:
    """Run emulation and return decoded stack string (best effort)."""
    ext = StackStringExtractor(code_bytes, base_addr)
    raw = ext.run_emulation()
    return raw.decode("utf-8", errors="ignore").strip("\x00")


def inject_into_program_model(program_model, address: int, code_bytes: bytes) -> Optional[str]:
    """Extract stack string at address and add as ProgramModel comment."""
    text = extract_stack_strings(code_bytes, address)
    if text and program_model:
        program_model.add_comment(address, f"stack: {text[:80]}")
        return text
    return None
