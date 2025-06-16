import os
import threading
import queue
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class DecompilerEngine(Enum):
    GHIDRA = "ghidra"
    RETDEC = "retdec"
    LLM4DECOMPILE = "llm4decompile"
    IDA_FREE = "ida_free"

class DecompilerManager:
    """Multi-engine decompilation manager for parallel analysis [6][17]"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engines = {}
        self.results_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def register_engine(self, engine_type, engine_instance):
        """Register a decompilation engine"""
        self.engines[engine_type] = engine_instance
        self.logger.info(f"Registered {engine_type.value} decompiler")
    
    def decompile_parallel(self, assembly_code, binary_path=None, engines=None):
        """
        Run multiple decompilation engines in parallel [17]
        
        Returns:
            dict: Results from each engine
        """
        if engines is None:
            engines = list(self.engines.keys())
        
        futures = {}
        results = {}
        
        # Submit jobs to thread pool
        for engine_type in engines:
            if engine_type in self.engines:
                future = self.executor.submit(
                    self._run_engine, 
                    engine_type, 
                    assembly_code, 
                    binary_path
                )
                futures[future] = engine_type
        
        # Collect results as they complete
        for future in as_completed(futures, timeout=300):  # 5 minute timeout
            engine_type = futures[future]
            try:
                result = future.result(timeout=60)
                results[engine_type] = {
                    'success': True,
                    'code': result,
                    'engine': engine_type.value
                }
                self.logger.info(f"{engine_type.value} decompilation completed")
            except Exception as e:
                results[engine_type] = {
                    'success': False,
                    'error': str(e),
                    'engine': engine_type.value
                }
                self.logger.error(f"{engine_type.value} decompilation failed: {e}")
        
        return results
    
    def _run_engine(self, engine_type, assembly_code, binary_path):
        """Execute a specific decompilation engine"""
        engine = self.engines[engine_type]
        
        if engine_type == DecompilerEngine.LLM4DECOMPILE:
            return engine.decompile_assembly(assembly_code)
        elif engine_type == DecompilerEngine.GHIDRA:
            return self._run_ghidra(binary_path) if binary_path else "Binary path required for Ghidra"
        elif engine_type == DecompilerEngine.RETDEC:
            return self._run_retdec(binary_path) if binary_path else "Binary path required for RetDec"
        else:
            return engine.decompile(assembly_code, binary_path)
    
    def _run_ghidra(self, binary_path):
        """Run Ghidra decompilation [24]"""
        try:
            import subprocess
            import tempfile
            
            # Create Ghidra script for headless analysis
            script_content = f'''
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

DecompInterface decompiler = new DecompInterface();
decompiler.openProgram(currentProgram);

FunctionManager funcMgr = currentProgram.getFunctionManager();
Function[] functions = funcMgr.getFunctions(true).toArray();

for (Function func : functions) {{
    if (func.getName().equals("main") || func.getName().equals("_start")) {{
        println("Decompiling: " + func.getName());
        println(decompiler.decompileFunction(func, 30, null).getDecompiledFunction().getC());
        break;
    }}
}}
'''
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            
            # Run Ghidra headless
            result = subprocess.run(
                ["analyzeHeadless", tempfile.gettempdir(), "temp_project", "-import", binary_path, "-postScript", script_path],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120
            )
            
            return result.stdout if result.returncode == 0 else f"Ghidra error: {result.stderr}"
            
        except Exception as e:
            return f"Ghidra execution failed: {str(e)}"
    
    def _run_retdec(self, binary_path):
        """Run RetDec decompilation [18]"""
        try:
            import subprocess
            
            try:
                result = subprocess.run(
                    ["retdec-decompiler", binary_path],
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120
                )
                if result.returncode == 0:
                    output_file = binary_path + ".c"
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                                return f.read()
                        except UnicodeDecodeError:
                            # Fallback to latin-1 if utf-8 fails
                            import warnings
                            warnings.warn(f"[WARN] Could not decode {output_file} as utf-8, falling back to latin-1.")
                            with open(output_file, 'r', encoding='latin-1', errors='replace') as f:
                                return f.read()
                    else:
                        return f"RetDec error: {result.stderr}"
                else:
                    return f"RetDec error: {result.stderr}"
            except subprocess.TimeoutExpired:
                return "[ERROR] RetDec timed out while decompiling."
            except Exception as e:
                return f"[ERROR] RetDec decompilation failed: {e}"
        except Exception as e:
            return f"RetDec execution failed: {str(e)}"
    
    def get_consensus_result(self, results):
        """
        Analyze multiple decompilation results and provide best consensus [6]
        """
        successful_results = {k: v for k, v in results.items() if v.get('success', False)}
        
        if not successful_results:
            return "All decompilation engines failed"
        
        # Prioritize LLM4Decompile results as they show superior performance
        if DecompilerEngine.LLM4DECOMPILE in successful_results:
            return successful_results[DecompilerEngine.LLM4DECOMPILE]['code']
        
        # Fallback to first successful result
        return list(successful_results.values())[0]['code']
