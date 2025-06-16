# -*- coding: utf-8 -*-

import logging
import re
from typing import List, Dict, Any

class DecompilerEngine:
    '''Basic decompiler engine for converting assembly to pseudo-code'''
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.functions = {}
        self.variables = {}
        self.current_function = None
    
    def decompile_function(self, instructions, start_address=None):
        '''Decompile a function from assembly instructions
        
        Args:
            instructions (list): List of assembly instructions
            start_address (int, optional): Starting address of the function
            
        Returns:
            str: Decompiled pseudo-code
        '''
        if not instructions:
            return ""
        
        if start_address is None:
            start_address = instructions[0]['address']
        
        self.current_function = f"func_{start_address:x}"
        self.variables = {}
        
        # Analyze the function
        self._analyze_function(instructions)
        
        # Generate pseudo-code
        pseudo_code = self._generate_pseudo_code(instructions)
        
        return pseudo_code
    
    def _analyze_function(self, instructions):
        '''Analyze function structure and variables'''
        # Simple analysis for demonstration
        for instruction in instructions:
            mnemonic = instruction['mnemonic']
            operands = instruction['op_str']
            
            # Look for stack variables
            if 'rbp' in operands or 'ebp' in operands:
                self._analyze_stack_variable(operands)
            
            # Look for register usage
            self._analyze_registers(mnemonic, operands)
    
    def _analyze_stack_variable(self, operands):
        '''Analyze stack variables'''
        # Match patterns like [rbp-0x10], [ebp+0x8], etc.
        pattern = r'\[(?:r?bp)([-+])(0x[0-9a-fA-F]+|\d+)\]'
        matches = re.findall(pattern, operands)
        
        for sign, offset in matches:
            if offset.startswith('0x'):
                offset_val = int(offset, 16)
            else:
                offset_val = int(offset)
            
            if sign == '-':
                var_name = f"local_{offset_val:x}"
            else:
                var_name = f"arg_{offset_val:x}"
            
            if var_name not in self.variables:
                self.variables[var_name] = {
                    'type': 'int',  # Default type
                    'offset': offset_val,
                    'sign': sign
                }
    
    def _analyze_registers(self, mnemonic, operands):
        '''Analyze register usage'''
        # Simple register analysis
        pass
    
    def _generate_pseudo_code(self, instructions):
        '''Generate pseudo-code from instructions'''
        lines = []
        
        # Function header
        lines.append(f"int {self.current_function}() {{")
        
        # Variable declarations
        for var_name, var_info in self.variables.items():
            lines.append(f"  {var_info['type']} {var_name};")
        
        if self.variables:
            lines.append("")
        
        # Process instructions
        indent = "  "
        for instruction in instructions:
            pseudo_line = self._instruction_to_pseudo(instruction)
            if pseudo_line:
                lines.append(indent + pseudo_line)
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def _instruction_to_pseudo(self, instruction):
        '''Convert a single instruction to pseudo-code'''
        mnemonic = instruction['mnemonic']
        operands = instruction['op_str']
        address = instruction['address']
        
        # Handle common instructions
        if mnemonic == 'mov':
            return self._handle_mov(operands)
        elif mnemonic == 'add':
            return self._handle_add(operands)
        elif mnemonic == 'sub':
            return self._handle_sub(operands)
        elif mnemonic == 'cmp':
            return self._handle_cmp(operands)
        elif mnemonic in ['je', 'jne', 'jl', 'jg', 'jle', 'jge']:
            return self._handle_jump(mnemonic, operands)
        elif mnemonic == 'call':
            return self._handle_call(operands)
        elif mnemonic == 'ret':
            return "return;"
        elif mnemonic == 'push':
            return f"// push {operands}"
        elif mnemonic == 'pop':
            return f"// pop {operands}"
        else:
            return f"// {mnemonic} {operands}"
    
    def _handle_mov(self, operands):
        '''Handle mov instructions'''
        parts = operands.split(', ')
        if len(parts) == 2:
            dst, src = parts
            dst = self._translate_operand(dst)
            src = self._translate_operand(src)
            return f"{dst} = {src};"
        return f"// mov {operands}"
    
    def _handle_add(self, operands):
        '''Handle add instructions'''
        parts = operands.split(', ')
        if len(parts) == 2:
            dst, src = parts
            dst = self._translate_operand(dst)
            src = self._translate_operand(src)
            return f"{dst} += {src};"
        return f"// add {operands}"
    
    def _handle_sub(self, operands):
        '''Handle sub instructions'''
        parts = operands.split(', ')
        if len(parts) == 2:
            dst, src = parts
            dst = self._translate_operand(dst)
            src = self._translate_operand(src)
            return f"{dst} -= {src};"
        return f"// sub {operands}"
    
    def _handle_cmp(self, operands):
        '''Handle cmp instructions'''
        parts = operands.split(', ')
        if len(parts) == 2:
            op1, op2 = parts
            op1 = self._translate_operand(op1)
            op2 = self._translate_operand(op2)
            return f"// compare {op1} with {op2}"
        return f"// cmp {operands}"
    
    def _handle_jump(self, mnemonic, operands):
        '''Handle conditional jumps'''
        target = self._translate_operand(operands)
        
        jump_map = {
            'je': 'if (equal)',
            'jne': 'if (not_equal)',
            'jl': 'if (less)',
            'jg': 'if (greater)',
            'jle': 'if (less_equal)',
            'jge': 'if (greater_equal)'
        }
        
        condition = jump_map.get(mnemonic, 'if')
        return f"{condition} goto {target};"
    
    def _handle_call(self, operands):
        '''Handle function calls'''
        target = self._translate_operand(operands)
        return f"call({target});"
    
    def _translate_operand(self, operand):
        '''Translate an operand to pseudo-code'''
        operand = operand.strip()
        
        # Handle immediate values
        if operand.startswith('0x'):
            return operand
        
        # Handle registers
        if operand in ['eax', 'rax']:
            return 'result'
        elif operand in ['ebx', 'rbx']:
            return 'var_b'
        elif operand in ['ecx', 'rcx']:
            return 'var_c'
        elif operand in ['edx', 'rdx']:
            return 'var_d'
        
        # Handle memory references
        if operand.startswith('[') and operand.endswith(']'):
            # Extract the memory reference
            mem_ref = operand[1:-1]
            
            # Check for stack variables
            for var_name, var_info in self.variables.items():
                offset_str = f"0x{var_info['offset']:x}" if var_info['offset'] > 9 else str(var_info['offset'])
                if f"bp{var_info['sign']}{offset_str}" in mem_ref:
                    return var_name
            
            return f"*({mem_ref})"
        
        # Default: return as-is
        return operand
