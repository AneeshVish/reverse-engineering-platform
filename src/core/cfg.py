from src.core.program_model import ProgramModel


class CFGGenerator:
    """Builds a control-flow graph from a list of instruction dicts.

    Nodes are *basic blocks* (keyed by start address) with real branch-target
    edges, rather than one node per instruction with only linear edges.
    """

    def __init__(self):
        pass

    def build_cfg(self, instructions):
        """Return a networkx DiGraph of basic blocks.

        Each instruction dict should have at least 'address', 'mnemonic',
        'op_str' (and ideally 'size').
        """
        model = ProgramModel(instructions=instructions)
        return model.build_cfg()
