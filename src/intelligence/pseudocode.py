"""
Simple x86/x64 disassembly to pseudocode converter for research and educational use.
Supports basic translation of common instructions to readable logic.
"""

def disasm_to_pseudocode(instructions):
    pseudocode = []
    addr_labels = {}
    # First pass: label jump targets (not needed for your sample, but future proof)
    for ins in instructions:
        if ins['mnemonic'] in ('jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb', 'call'):
            try:
                target = int(ins['op_str'], 16)
                addr_labels[target] = f'label_{target:x}'
            except Exception:
                pass
    # Second pass: translate instructions
    for ins in instructions:
        addr = ins['address']
        mnem = ins['mnemonic']
        op = ins['op_str']
        if addr in addr_labels:
            pseudocode.append(f"{addr_labels[addr]}:")
        if mnem == 'lea':
            pseudocode.append(f"rax = {op.split(',')[1].strip()}  # {mnem} {op}")
        elif mnem == 'mov':
            pseudocode.append(f"{op.split(',')[0].strip()} = {op.split(',')[1].strip()}  # {mnem} {op}")
        elif mnem == 'ret':
            pseudocode.append("return")
        elif mnem == 'int3':
            pseudocode.append("# int3 (breakpoint/padding)")
        else:
            pseudocode.append(f"{mnem} {op}")
    return '\n'.join(pseudocode)

# Example usage for testing:
if __name__ == "__main__":
    sample = [
        {'address': 4096, 'bytes': b'H\x8d\x05\xe1D\x01\x00', 'mnemonic': 'lea', 'op_str': 'rax, [rip + 0x144e1]', 'size': 7},
        {'address': 4103, 'bytes': b'H\x89A\x08', 'mnemonic': 'mov', 'op_str': 'qword ptr [rcx + 8], rax', 'size': 4},
        {'address': 4107, 'bytes': b'H\x8d\x05\xbeD\x01\x00', 'mnemonic': 'lea', 'op_str': 'rax, [rip + 0x144be]', 'size': 7},
        {'address': 4114, 'bytes': b'H\x89\x01', 'mnemonic': 'mov', 'op_str': 'qword ptr [rcx], rax', 'size': 3},
        {'address': 4117, 'bytes': b'H\x8b\xc1', 'mnemonic': 'mov', 'op_str': 'rax, rcx', 'size': 3},
        {'address': 4120, 'bytes': b'\xc3', 'mnemonic': 'ret', 'op_str': '', 'size': 1},
        {'address': 4121, 'bytes': b'\xcc', 'mnemonic': 'int3', 'op_str': '', 'size': 1},
    ]
    print(disasm_to_pseudocode(sample))
