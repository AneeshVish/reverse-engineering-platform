import os
import logging
import lief
from capstone import *
from src.intelligence import pseudocode
logger = logging.getLogger(__name__)


class MultiArchDisassembler:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary = lief.parse(binary_path)
        self.arch = self._detect_arch_string()
        self.bits = self._detect_bits()
        try:
            self.cs_arch, self.cs_mode = self.detect_arch_mode()
        except Exception as e:
            logger.error(f"[ERROR] Could not detect architecture for {binary_path}: {e}")
            self.cs_arch, self.cs_mode = CS_ARCH_X86, CS_MODE_64
        self.disassembler = Cs(self.cs_arch, self.cs_mode)

    def detect_arch_mode(self):
        # Robust arch/mode detection for PE, ELF, MachO
        header = self.binary.header
        bits = self._detect_bits()
        cpu_type = ''
        machine_type = ''
        mt = ''  # Always initialize mt
        if hasattr(header, 'cpu_type') and header.cpu_type is not None:
            cpu_type = str(header.cpu_type).upper()
        if hasattr(header, 'machine_type') and header.machine_type is not None:
            machine_type = str(header.machine_type).upper()
            mt = machine_type
        else:
            # fallback: try cpu_type or set to 'UNKNOWN'
            mt = cpu_type if cpu_type else 'UNKNOWN'
        # x86/x86_64
        if 'X86_64' in mt or 'AMD64' in mt:
            return CS_ARCH_X86, CS_MODE_64
        elif 'I386' in mt or 'X86' in mt:
            return CS_ARCH_X86, CS_MODE_32
        # ARM
        elif 'ARM64' in mt or 'AARCH64' in mt:
            return CS_ARCH_ARM64, CS_MODE_ARM
        elif 'ARM' in mt:
            return CS_ARCH_ARM, CS_MODE_ARM
        # MIPS
        elif 'MIPS' in mt:
            return CS_ARCH_MIPS, CS_MODE_MIPS64 if bits == 64 else CS_MODE_MIPS32
        # PPC
        elif 'POWERPC' in mt or 'PPC' in mt:
            return CS_ARCH_PPC, CS_MODE_64 if bits == 64 else CS_MODE_32
        # RISCV
        elif 'RISCV' in mt:
            return CS_ARCH_RISCV, CS_MODE_RISCV64 if bits == 64 else CS_MODE_RISCV32
        # Default fallback
        logger.warning(f"[WARN] Unknown architecture string '{mt}'. Falling back to x86_64.")
        return CS_ARCH_X86, CS_MODE_64



    def _detect_arch_string(self):
        header = self.binary.header
        if hasattr(header, 'cpu_type') and header.cpu_type is not None:
            return str(header.cpu_type)
        elif hasattr(header, 'machine_type') and header.machine_type is not None:
            return str(header.machine_type)
        else:
            return 'UNKNOWN'

    def _detect_bits(self):
        header = self.binary.header
        if hasattr(header, 'identity_class') and hasattr(header.identity_class, 'value'):
            return header.identity_class.value * 32
        return 64

    def get_text_section(self):
        for section in self.binary.sections:
            if section.name in ['.text', '__text', 'CODE']:
                return section
        return None

    def disassemble(self):
        section = self.get_text_section()
        if not section:
            return []
        code = section.content
        addr = section.virtual_address
        instructions = []
        for insn in self.disassembler.disasm(bytes(code), addr):
            instructions.append({
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str
            })
        return instructions

    def to_pseudocode(self):
        """
        Disassemble and convert to pseudocode using the intelligence.pseudocode module.
        Returns a string of pseudocode.
        """
        instructions = self.disassemble()
        return pseudocode.disasm_to_pseudocode(instructions)