import networkx as nx

class CFGGenerator:
    def __init__(self):
        pass

    def build_cfg(self, instructions):
        """
        Build a control flow graph from a list of instructions.
        Each instruction should be a dict with at least 'address', 'mnemonic', and 'op_str'.
        """
        G = nx.DiGraph()
        last_addr = None
        for instr in instructions:
            addr = instr.get('address')
            G.add_node(addr, mnemonic=instr.get('mnemonic'), op_str=instr.get('op_str'))
            if last_addr is not None:
                G.add_edge(last_addr, addr)
            last_addr = addr
            # TODO: Add edges for jumps/calls/branches based on mnemonic/op_str
        return G
