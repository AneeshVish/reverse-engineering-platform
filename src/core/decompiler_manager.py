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
    
    def _run_engine(self, engine_type, analysis_log, binary_path):
        """
        Execute a specific decompilation engine. For the AI decompiler (LLM4DECOMPILE), use analysis logs as input.
        """
        engine = self.engines[engine_type]

        if engine_type == DecompilerEngine.LLM4DECOMPILE:
            # Use the new method and pass the full analysis log
            return engine.decompile_analysis_log(analysis_log)
        elif engine_type == DecompilerEngine.GHIDRA:
            return self._run_ghidra(binary_path) if binary_path else "Binary path required for Ghidra"
        elif engine_type == DecompilerEngine.RETDEC:
            return self._run_retdec(binary_path) if binary_path else "Binary path required for RetDec"
        else:
            return engine.decompile(analysis_log, binary_path)
    
    def _run_ghidra(self, binary_path):
        """Run Ghidra decompilation [24] with detailed logging for debugging."""
        import logging
        logger = logging.getLogger("DecompilerManager._run_ghidra")
        try:
            import subprocess
            import tempfile
            
            # Create Ghidra Python (Jython) script for headless analysis
            script_content = '''
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

if currentProgram is None:
    print("[ERROR] No program loaded.")
    exit()

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)

for func in functions:
    try:
        print("Decompiling: " + func.getName())
        res = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        print(res.getDecompiledFunction().getC())
        print("=")
        print("=" * 60)
        print("=")
    except Exception as e:
        print("[ERROR] Failed to decompile function {}: {}".format(func.getName(), e))
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                script_path = f.name
            import uuid
            import shutil
            # Use a unique temp project directory for each run
            project_dir = os.path.join(tempfile.gettempdir(), f"ghidra_project_{uuid.uuid4().hex}")
            os.makedirs(project_dir, exist_ok=True)
            logger.info(f"[GHIDRA SCRIPT PATH] {script_path}")
            logger.info(f"[GHIDRA TEMP PROJECT DIR] {project_dir}")
            logger.info(f"[GHIDRA BINARY PATH] {binary_path}")
            ghidra_cmd = [r"D:\C\Downloads\ghidra_11.3.2_PUBLIC_20250415\ghidra_11.3.2_PUBLIC\support\analyzeHeadless.bat", project_dir, "temp_project", "-import", binary_path, "-postScript", script_path]
            logger.info(f"[GHIDRA CMD] {' '.join(ghidra_cmd)}")
            result = subprocess.run(
                ghidra_cmd,
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=7200
            )
            # Clean up temp project dir
            try:
                shutil.rmtree(project_dir, ignore_errors=True)
            except Exception as cleanup_exc:
                logger.warning(f"[GHIDRA CLEANUP] Failed to remove temp project dir: {cleanup_exc}")
            logger.info(f"[GHIDRA STDOUT]\n{result.stdout}")
            logger.error(f"[GHIDRA STDERR]\n{result.stderr}")
            # --- VERBOSE ERROR OUTPUT ---
            if result.returncode != 0:
                logger.error("[GHIDRA VERBOSE ERROR]")
                logger.error(f"  Command: {' '.join(ghidra_cmd)}")
                logger.error(f"  Return code: {result.returncode}")
                logger.error(f"  STDOUT: {result.stdout}")
                logger.error(f"  STDERR: {result.stderr}")
                print("[GHIDRA VERBOSE ERROR]")
                print(f"  Command: {' '.join(ghidra_cmd)}")
                print(f"  Return code: {result.returncode}")
                print(f"  STDOUT: {result.stdout}")
                print(f"  STDERR: {result.stderr}")
                return f"Ghidra error (verbose):\nCommand: {' '.join(ghidra_cmd)}\nReturn code: {result.returncode}\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            else:
                return result.stdout  # FULL C code output, even if very large
        except Exception as e:
            import traceback
            logger.error(f"Ghidra execution failed: {str(e)}")
            logger.error(traceback.format_exc())
            print("[GHIDRA EXCEPTION]")
            print(traceback.format_exc())
            return f"Ghidra execution failed: {str(e)}\n{traceback.format_exc()}"
    
    def _run_retdec(self, binary_path):
        """Run RetDec decompilation [18]"""
        try:
            import subprocess
            
            try:
                result = subprocess.run(
                    ["retdec-decompiler", binary_path],
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=800
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
