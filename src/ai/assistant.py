# -*- coding: utf-8 -*-

import logging
import openai
from typing import List, Dict, Optional
import json

class AIAssistant:
    '''AI assistant for binary analysis using OpenAI API'''
    
    def __init__(self, api_key: str = "", model: str = "gpt-3.5-turbo"):
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key
        self.model = model
        self.client = None
        
        if api_key:
            self.initialize()
    
    def initialize(self):
        '''Initialize the AI client'''
        try:
            openai.api_key = self.api_key
            self.client = openai
            self.logger.info("AI Assistant initialized")
            return True
        except Exception as e:
            self.logger.error(f"Error initializing AI Assistant: {e}")
            return False
    
    def analyze_function(self, instructions: List[Dict], context: str = "") -> str:
        '''Analyze a function using AI'''
        if not self.client:
            return "AI Assistant not initialized"
        
        asm_code = self._format_instructions_for_ai(instructions)
        
        prompt = f"Analyze this assembly code and provide insights:\n\nContext: {context}\n\nAssembly Code:\n{asm_code}\n\nPlease provide function purpose, key operations, and potential vulnerabilities."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert reverse engineer analyzing assembly code."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {e}")
            return f"Error in AI analysis: {e}"
    
    def _format_instructions_for_ai(self, instructions: List[Dict]) -> str:
        '''Format instructions for AI consumption'''
        formatted_lines = []
        
        for instr in instructions[:50]:  # Limit to first 50 instructions
            address = f"0x{instr['address']:08x}"
            mnemonic = instr['mnemonic']
            operands = instr['op_str']
            formatted_lines.append(f"{address}: {mnemonic} {operands}")
        
        if len(instructions) > 50:
            formatted_lines.append("... (truncated)")
        
        return "\n".join(formatted_lines)

class ModelInterface:
    '''Interface for different AI models'''
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.available_models = {
            'openai': AIAssistant,
        }
    
    def get_assistant(self, model_type: str = 'openai', **kwargs) -> Optional[AIAssistant]:
        '''Get an AI assistant instance'''
        if model_type in self.available_models:
            try:
                return self.available_models[model_type](**kwargs)
            except Exception as e:
                self.logger.error(f"Error creating {model_type} assistant: {e}")
                return None
        else:
            self.logger.error(f"Unknown model type: {model_type}")
            return None
