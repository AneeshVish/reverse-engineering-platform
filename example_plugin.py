# -*- coding: utf-8 -*-

from src.plugins.base_plugin import BasePlugin
import logging

class StringAnalyzerPlugin(BasePlugin):
    '''Example plugin that analyzes strings in binary files'''
    
    def __init__(self):
        super().__init__()
        self.name = "String Analyzer"
        self.description = "Analyzes strings found in binary files"
        self.version = "1.0.0"
        self.author = "RE Platform Team"
        self.logger = logging.getLogger(__name__)
    
    def on_load(self):
        '''Called when the plugin is loaded'''
        self.logger.info(f"Plugin {self.name} loaded")
    
    def on_unload(self):
        '''Called when the plugin is unloaded'''
        self.logger.info(f"Plugin {self.name} unloaded")
    
    def on_binary_load(self, binary_info):
        '''Called when a binary is loaded'''
        self.logger.info(f"Analyzing strings in {binary_info.get('type', 'unknown')} binary")
        
        # Example: Extract printable strings (this is a simplified example)
        strings = self._extract_strings(binary_info)
        
        if strings:
            self.logger.info(f"Found {len(strings)} strings")
            for i, string in enumerate(strings[:10]):  # Show first 10
                self.logger.info(f"  {i+1}: {string}")
            
            if len(strings) > 10:
                self.logger.info(f"  ... and {len(strings) - 10} more")
    
    def on_disassembly(self, instructions):
        '''Called when disassembly is performed'''
        self.logger.info(f"Plugin received {len(instructions)} instructions")
        
        # Example: Look for string references in instructions
        string_refs = self._find_string_references(instructions)
        
        if string_refs:
            self.logger.info(f"Found {len(string_refs)} string references")
    
    def on_analysis(self, analysis_results):
        '''Called when analysis is performed'''
        self.logger.info("Plugin received analysis results")
    
    def _extract_strings(self, binary_info):
        '''Extract strings from binary (placeholder implementation)'''
        # This is a simplified example
        # In a real implementation, you would parse the binary sections
        return ["example_string_1", "example_string_2", "example_string_3"]
    
    def _find_string_references(self, instructions):
        '''Find string references in instructions'''
        string_refs = []
        
        for instruction in instructions:
            # Look for instructions that might reference strings
            if instruction['mnemonic'] in ['lea', 'mov'] and 'rip' in instruction['op_str']:
                string_refs.append(instruction)
        
        return string_refs

def register_plugin():
    '''Register the plugin with the plugin manager'''
    return StringAnalyzerPlugin()
