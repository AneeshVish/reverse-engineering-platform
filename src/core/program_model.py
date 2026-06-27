"""Structured in-memory model of a disassembled program.

Historically several features (CFG, pseudocode, re-analyze) reconstructed their
input by re-parsing the *text* shown in a QTextEdit/table. That is lossy and
fragile. This module is the single structured source of truth: instructions,
basic blocks, and a real control-flow graph with branch-target edges.

Instructions are plain dicts (as produced by DisassemblerEngine.disassemble):
    {'address': int, 'mnemonic': str, 'op_str': str, 'size': int, 'bytes': bytes}
"""

from dataclasses import dataclass, field


# --- instruction classification (x86 + ARM/AArch64) -------------------------

# AArch64 / ARM conditional branches (explicit set: 'b'-prefixed data ops like
# 'bic'/'bfi' must NOT be treated as branches).
_ARM_COND = {
    "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc",
    "bhi", "bls", "bge", "blt", "bgt", "ble", "cbz", "cbnz", "tbz", "tbnz",
}
_RET = {"ret", "retn", "retf", "reti", "iret", "iretd", "iretq"}
_CALL = {"call", "bl", "blx", "blr"}
_UNCOND = {"jmp", "b", "bx", "br"}


def classify(mnemonic):
    """Return one of: 'cond', 'uncond', 'call', 'ret', 'other'."""
    m = (mnemonic or "").lower()
    if m in _RET:
        return "ret"
    if m in _CALL:
        return "call"
    if m in _UNCOND:
        return "uncond"
    if m.startswith("j"):          # x86 conditional jumps (je/jne/jg/...) and jmp handled above
        return "cond"
    if m.startswith("b.") or m in _ARM_COND:
        return "cond"
    return "other"


def branch_target(op_str):
    """Best-effort absolute branch target parsed from an operand string.

    Handles 'jmp 0x401000', 'b #0x1000', 'b.eq 0x1234'. Returns None for
    indirect/register/memory targets (e.g. 'jmp rax', 'br x0', '[rax]').
    """
    if not op_str:
        return None
    tok = op_str.strip().split(",")[0].split()[0].lstrip("#")
    if tok.startswith("0x"):
        try:
            return int(tok, 16)
        except ValueError:
            return None
    return None


# --- model ------------------------------------------------------------------

@dataclass
class BasicBlock:
    start: int
    instructions: list = field(default_factory=list)
    successors: list = field(default_factory=list)   # resolved block-start addresses

    @property
    def end(self):
        """Address of the last instruction in the block (0 if empty)."""
        return self.instructions[-1]["address"] if self.instructions else self.start

    def label(self, max_lines=4):
        lines = [f"0x{self.start:x}"]
        for ins in self.instructions[:max_lines]:
            lines.append(f"{ins.get('mnemonic', '')} {ins.get('op_str', '')}".strip())
        if len(self.instructions) > max_lines:
            lines.append("...")
        return "\n".join(lines)


class ProgramModel:
    """Holds the structured result of analyzing one binary."""

    def __init__(self, instructions=None, sections=None, file_path=None,
                 file_type=None, arch=None):
        self.instructions = list(instructions or [])
        self.sections = list(sections or [])
        self.file_path = file_path
        self.file_type = file_type
        self.arch = arch
        self._blocks = None

    # -- construction --------------------------------------------------------

    @classmethod
    def from_results(cls, results):
        """Build from a BinaryAnalysisWorker result dict."""
        info = results.get("binary_info", {}) if results else {}
        return cls(
            instructions=results.get("instructions", []) if results else [],
            sections=results.get("sections", []) if results else [],
            file_path=results.get("file_path") if results else None,
            file_type=info.get("type"),
            arch=info.get("arch"),
        )

    # -- basic blocks --------------------------------------------------------

    def basic_blocks(self):
        """Return basic blocks, computing (and caching) them on first use."""
        if self._blocks is None:
            self._blocks = self._build_basic_blocks()
        return self._blocks

    def _build_basic_blocks(self):
        ins = sorted(self.instructions, key=lambda i: i.get("address", 0))
        if not ins:
            return []
        addrs = {i["address"] for i in ins}

        # 1. Determine leaders (block-start addresses).
        leaders = {ins[0]["address"]}
        for idx, i in enumerate(ins):
            cls = classify(i.get("mnemonic"))
            if cls in ("cond", "uncond", "call", "ret"):
                # instruction after a flow-control op begins a new block
                if idx + 1 < len(ins):
                    leaders.add(ins[idx + 1]["address"])
                # the branch target begins a new block (if we have it)
                tgt = branch_target(i.get("op_str"))
                if tgt is not None and tgt in addrs:
                    leaders.add(tgt)

        # 2. Slice instructions into blocks at leaders.
        blocks = []
        current = None
        for i in ins:
            if i["address"] in leaders or current is None:
                current = BasicBlock(start=i["address"])
                blocks.append(current)
            current.instructions.append(i)

        # 3. Resolve successors.
        block_starts = {b.start for b in blocks}
        for bi, block in enumerate(blocks):
            last = block.instructions[-1]
            cls = classify(last.get("mnemonic"))
            fallthrough = blocks[bi + 1].start if bi + 1 < len(blocks) else None
            tgt = branch_target(last.get("op_str"))
            succ = []
            if cls == "uncond":
                if tgt in block_starts:
                    succ.append(tgt)
            elif cls == "cond":
                if tgt in block_starts:
                    succ.append(tgt)
                if fallthrough is not None:
                    succ.append(fallthrough)
            elif cls == "ret":
                pass  # no intraprocedural successor
            else:  # call / other -> fall through
                if fallthrough is not None:
                    succ.append(fallthrough)
            # de-dup, preserve order
            block.successors = list(dict.fromkeys(succ))
        return blocks

    # -- views ---------------------------------------------------------------

    def build_cfg(self):
        """Return a networkx DiGraph of basic blocks (nodes keyed by start addr)."""
        import networkx as nx
        g = nx.DiGraph()
        for block in self.basic_blocks():
            g.add_node(block.start, label=block.label(), mnemonic=block.label(max_lines=1))
        for block in self.basic_blocks():
            for succ in block.successors:
                g.add_edge(block.start, succ)
        return g

    def assembly_text(self):
        """Flat assembly listing (for AI decompilation / export)."""
        return "\n".join(
            f"{i.get('mnemonic', '')} {i.get('op_str', '')}".strip()
            for i in self.instructions
        )

    def stats(self):
        blocks = self.basic_blocks()
        edges = sum(len(b.successors) for b in blocks)
        return {
            "instructions": len(self.instructions),
            "basic_blocks": len(blocks),
            "edges": edges,
            "sections": len(self.sections),
        }
