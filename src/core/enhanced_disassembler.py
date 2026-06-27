from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
import logging

class EnhancedDisassembler:
    def __init__(self):
        self.md = None
        self.logger = logging.getLogger(__name__)

    def auto_disassemble(self, data, base_addr=0):
        for arch, mode in [
            (CS_ARCH_X86, CS_MODE_32),
            (CS_ARCH_X86, CS_MODE_64),
            (CS_ARCH_ARM, CS_MODE_ARM),
            (CS_ARCH_ARM64, CS_MODE_ARM)
        ]:
            try:
                self.md = Cs(arch, mode)
                self.md.skipdata = True
                return [
                    f"0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}"
                    for ins in self.md.disasm(data, base_addr)
                ]
            except Exception:
                continue
        return ["Disassembly failed"]
