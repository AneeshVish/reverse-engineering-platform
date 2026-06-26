import logging
import subprocess
import tempfile
import os
from pathlib import Path


class AIDecompiler:
    """
    AI-powered decompiler using Ollama LLM for converting analysis logs or assembly to C code.
    Only Ollama is supported as backend. This class is backend-agnostic for analysis log input.
    """
    def __init__(self, ollama_model="llama3.2"):
        self.logger = logging.getLogger(__name__)
        self.ollama_model = ollama_model
        self._check_ollama_available()
    
    def _check_ollama_available(self):
        """Check if Ollama is available for local inference."""
        try:
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
            self.logger.error(f"Failed to check Ollama availability: {e}")
    
    def decompile_analysis_log(self, analysis_log: str) -> str:
        """
        Decompile an analysis log (assembly, disassembly, or other analysis text) to C code using Ollama LLM.

        Args:
            analysis_log (str): The analysis log or disassembly to convert.

        Returns:
            str: Decompiled C code (Ollama output)
        """
        improved_prompt = (
            "Given the following binary analysis log, reconstruct the original C source code as accurately as possible.\n"
            "- Only output valid C code (no explanations, no wrappers for assembly instructions).\n"
            "- Use real function names and logic from the log.\n"
            "- Do not invent code or create placeholder functions.\n"
            "- If the log is insufficient to reconstruct real logic, output a C comment warning about missing information.\n"
            "- Do not output any text except C code or C comments.\n\n"
            "Analysis log:\n"
            f"{analysis_log}\n"
        )
        return self._decompile_with_ollama(improved_prompt)

    @staticmethod
    def is_upx_packed(binary_path):
        """Detect if a binary is UPX-packed by scanning for UPX section names or signatures."""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
                if b'UPX!' in data or b'.UPX' in data or b'UPX0' in data or b'UPX1' in data:
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def auto_unpack_upx(binary_path):
        """Attempt to auto-unpack a UPX-packed binary using upx.exe (Windows only). Returns path to unpacked binary or None."""
        import shutil
        import subprocess
        import os
        upx_path = shutil.which('upx') or shutil.which('upx.exe')
        if not upx_path:
            return None
        unpacked_path = binary_path + '.unpacked'
        try:
            result = subprocess.run([upx_path, '-d', '-o', unpacked_path, binary_path], capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and os.path.exists(unpacked_path):
                return unpacked_path
        except Exception:
            pass
        return None

    
    def _decompile_with_ollama(self, input_text):
        """Decompile using Ollama local inference."""
        import shutil
        try:
            # If input_text is very large, write to a temp file and use input redirection if supported
            max_direct_arg = 8000  # Conservative CLI arg limit; adjust if Ollama supports more
            use_file = len(input_text) > max_direct_arg
            temp_file = None
            if use_file:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
                    f.write(input_text)
                    temp_file = f.name
                # Use input redirection if Ollama supports it, else pass as file argument if supported
                # Try: ollama run <model> < input.txt
                # On Windows, input redirection for subprocess: use shell=True
                command = f'ollama run {self.ollama_model} < "{temp_file}"'
                result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300, shell=True)
            else:
                result = subprocess.run([
                    "ollama", "run", self.ollama_model, input_text
                ], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
            if temp_file:
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return f"Ollama decompilation failed: {result.stderr}"
        except Exception as e:
            self.logger.error(f"Ollama decompilation failed: {e}")
            return f"Decompilation error: {str(e)}"

    


    def enhance_ghidra_output(self, ghidra_code):
        """
        Refine Ghidra decompilation output using Ollama AI.
        This will attempt to improve variable names, comments, and code structure.
        """
        enhancement_prompt = (
            "Please improve this decompiled code by:\n"
            "1. Adding meaningful variable names\n"
            "2. Adding helpful comments\n"
            "3. Improving code structure\n"
            "4. Identifying potential vulnerabilities\n\n"
            "Original code:\n"
            f"{ghidra_code}\n\nImproved code (C):\n"
        )
        return self._decompile_with_ollama(enhancement_prompt)
