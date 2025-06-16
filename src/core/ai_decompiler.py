import logging
import subprocess
import tempfile
import os
from pathlib import Path

import torch



class AIDecompiler:
    """LLM4Decompile integration for AI-powered decompilation [6][9]"""
    
    def __init__(self, model_type="ollama"):
        self.logger = logging.getLogger(__name__)
        self.model_type = model_type
        self.model = None
        self.tokenizer = None
        self.ollama_model = "llama3.2"  # Easily configurable model name
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the LLM4Decompile model [16]"""
        if self.model_type == "ollama":
            try:
                # Check if Ollama is available
                result = subprocess.run(
                    ["ollama", "list"], 
                    capture_output=True, 
                    text=True, encoding='utf-8', errors='replace', 
                    timeout=10
                )
                if result.returncode == 0:
                    self.logger.info("Ollama is available for local inference")
                else:
                    self.logger.warning("Ollama not found, using fallback mode")
            except Exception as e:
                self.logger.error(f"Failed to initialize Ollama: {e}")
        
        elif self.model_type == "huggingface":
            try:
                from transformers import AutoTokenizer, AutoModelForCausalLM
                import torch
                
                model_path = "LLM4Binary/llm4decompile-6.7b-v1.5"
                self.tokenizer = AutoTokenizer.from_pretrained(model_path)
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_path, 
                    torch_dtype=torch.bfloat16,
                    device_map="auto"
                )
                self.logger.info("HuggingFace LLM4Decompile model loaded")
            except Exception as e:
                self.logger.error(f"Failed to load HuggingFace model: {e}")
    
    def decompile_assembly(self, assembly_code, optimization_level="O0"):
        """
        Decompile assembly code to C using LLM4Decompile [6][16]
        
        Args:
            assembly_code (str): Assembly instructions to decompile
            optimization_level (str): Compiler optimization level
        
        Returns:
            str: Decompiled C code
        """
        # Format assembly for LLM4Decompile
        formatted_input = f"""# This is the assembly code with {optimization_level} optimization:
{assembly_code}
# What is the source code?
"""
        
        if self.model_type == "ollama":
            return self._decompile_with_ollama(formatted_input)
        elif self.model_type == "huggingface":
            return self._decompile_with_huggingface(formatted_input)
        
        return "AI decompilation not available - using fallback analysis"
    
    def _decompile_with_ollama(self, input_text):
        """Decompile using Ollama local inference [16]"""
        try:
            # Create temporary file for input
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(input_text)
                temp_file = f.name
            
            # Run Ollama command
            result = subprocess.run([
                "ollama", "run", self.ollama_model,  # Use available model
                f"Please analyze this assembly code and provide equivalent C code: {input_text[:500]}..."
            ], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)  # Increased timeout to 180s for large/complex code
            
            os.unlink(temp_file)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Ollama decompilation failed: {result.stderr}"
                
        except Exception as e:
            self.logger.error(f"Ollama decompilation failed: {e}")
            return f"Decompilation error: {str(e)}"
    
    def _decompile_with_huggingface(self, input_text):
        """Decompile using HuggingFace transformers [6]"""
        try:
            if not self.model or not self.tokenizer:
                return "HuggingFace model not available"
            
            inputs = self.tokenizer(input_text, return_tensors="pt").to(self.model.device)
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=1024,
                    temperature=0.1,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Extract only the generated part
            decompiled = generated_text[len(input_text):].strip()
            return decompiled
            
        except Exception as e:
            self.logger.error(f"HuggingFace decompilation failed: {e}")
            return f"Decompilation error: {str(e)}"

    def enhance_ghidra_output(self, ghidra_code):
        """Refine Ghidra decompilation output using AI [24]"""
        enhancement_prompt = f"""
        Please improve this decompiled code by:
        1. Adding meaningful variable names
        2. Adding helpful comments
        3. Improving code structure
        4. Identifying potential vulnerabilities

        Original code:
        {ghidra_code}

        Improved code:
        """
        
        if self.model_type == "ollama":
            return self._decompile_with_ollama(enhancement_prompt)
        return ghidra_code
