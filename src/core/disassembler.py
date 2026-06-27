# -*- coding: utf-8 -*-

import logging
from capstone import (
    Cs, CsError,
    CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM,
)
from enum import Enum

logger = logging.getLogger(__name__)

# Safety cap: a multi-MB code section can produce millions of instructions, which
# floods memory/UI and makes the app appear to hang. Stop after this many.
MAX_INSTRUCTIONS = 400_000


class Architecture(Enum):
    X86 = 1
    X86_64 = 2
    ARM = 3
    ARM64 = 4


class DisassemblerEngine:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.md = None

    def initialize(self, architecture, mode=None):
        """Initialize Capstone for the given architecture. Returns True on success."""
        try:
            # An architecture-appropriate NOP used only to self-test the engine
            # (an x86 NOP is invalid on ARM, which used to make ARM init fail).
            if architecture == Architecture.X86_64:
                self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                test_code = b'\x90'                      # nop
            elif architecture == Architecture.X86:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
                test_code = b'\x90'                      # nop
            elif architecture == Architecture.ARM64:
                self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                test_code = b'\x1f\x20\x03\xd5'          # nop (AArch64)
            elif architecture == Architecture.ARM:
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                test_code = b'\x00\xf0\x20\xe3'          # nop (ARM A32)
            else:
                self.logger.error(f"Unsupported architecture: {architecture}")
                return False

            self.md.detail = True
            self.md.skipdata = True  # Critical for handling mixed code/data

            test_result = list(self.md.disasm(test_code, 0))
            ok = len(test_result) > 0
            self.logger.debug("Disassembler initialized for %s (self-test %s)",
                              architecture, "ok" if ok else "FAILED")
            return ok
        except Exception as e:
            self.logger.error(f"Disassembler initialization error: {e}")
            return False

    def disassemble(self, code, address=0, chunk_size=0x1000, max_instructions=MAX_INSTRUCTIONS):
        """Disassemble `code` starting at `address`. Returns a list of instruction dicts.

        Stops at `max_instructions` to avoid runaway output on very large sections.
        """
        if not self.md:
            self.logger.debug("disassemble() called before initialize()")
            return []

        instructions = []
        try:
            self.logger.debug("Disassembling %d bytes at 0x%08x", len(code), address)
            for offset in range(0, len(code), chunk_size):
                chunk = code[offset:offset + chunk_size]
                chunk_addr = address + offset
                for insn in self.md.disasm(chunk, chunk_addr):
                    instructions.append({
                        'address': insn.address,
                        'bytes': bytes(insn.bytes),
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'size': insn.size,
                    })
                    if len(instructions) >= max_instructions:
                        self.logger.debug("Reached instruction cap (%d); truncating.",
                                          max_instructions)
                        return instructions
        except CsError as e:
            self.logger.error(f"Capstone disassembly error: {e}")
        except Exception as e:
            self.logger.error(f"Disassembly error: {e}")

        self.logger.debug("Generated %d instructions", len(instructions))
        return instructions
