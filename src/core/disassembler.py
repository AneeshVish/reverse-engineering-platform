# -*- coding: utf-8 -*-

import logging
from capstone import (
    Cs, CsError,
    CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM,
)
from enum import Enum

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
        """Initialize with enhanced error handling"""
        try:
            # Set architecture and mode
            if architecture == Architecture.X86_64:
                self.md = Cs(CS_ARCH_X86, CS_MODE_64)
                print("[DEBUG] Initialized x64 disassembler")
            elif architecture == Architecture.X86:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
                print("[DEBUG] Initialized x86 disassembler")
            elif architecture == Architecture.ARM64:
                self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                print("[DEBUG] Initialized ARM64 disassembler")
            elif architecture == Architecture.ARM:
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                print("[DEBUG] Initialized ARM disassembler")
            else:
                self.logger.error(f"Unsupported architecture: {architecture}")
                return False
                
            self.md.detail = True
            self.md.skipdata = True  # Critical for handling mixed code/data
            
            # Test disassembler with simple instruction
            test_code = b'\x90'  # NOP instruction
            test_result = list(self.md.disasm(test_code, 0))
            if len(test_result) > 0:
                print("[DEBUG] Disassembler test successful")
                return True
            else:
                print("[DEBUG] Disassembler test failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Disassembler initialization error: {e}")
            print(f"[DEBUG] Disassembler init exception: {e}")
            return False

    def disassemble(self, code, address=0, chunk_size=0x1000):
        """Enhanced disassembly with detailed logging"""
        if not self.md:
            print("[DEBUG] Disassembler not initialized")
            return []

        instructions = []
        try:
            print(f"[DEBUG] Disassembling {len(code)} bytes at 0x{address:08x}")
            
            # Process in chunks
            for offset in range(0, len(code), chunk_size):
                chunk = code[offset:offset+chunk_size]
                chunk_addr = address + offset
                
                chunk_instructions = 0
                for insn in self.md.disasm(chunk, chunk_addr):
                    instructions.append({
                        'address': insn.address,
                        'bytes': bytes(insn.bytes),
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'size': insn.size
                    })
                    chunk_instructions += 1
                    
                if chunk_instructions > 0:
                    print(f"[DEBUG] Chunk at 0x{chunk_addr:08x}: {chunk_instructions} instructions")
                    
        except CsError as e:
            self.logger.error(f"Capstone disassembly error: {e}")
            print(f"[DEBUG] Capstone error: {e}")
        except Exception as e:
            self.logger.error(f"Disassembly error: {e}")
            print(f"[DEBUG] Disassembly exception: {e}")
        
        print(f"[DEBUG] Total instructions generated: {len(instructions)}")
        return instructions