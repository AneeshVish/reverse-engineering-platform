# -*- coding: utf-8 -*-
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QStatusBar, QFileDialog, QPushButton,
    QProgressBar, QLabel, QComboBox, QCheckBox, QLineEdit, QInputDialog,
    QApplication, QDockWidget, QToolBar, QToolButton, QFrame, QSizePolicy,
) # All widgets imported at top

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QAction, QActionGroup, QShortcut, QKeySequence

from src.gui import theme as theme_mod
from src.gui.icons import icon as qicon
from src.gui.insights_panel import InsightsPanel
from src.gui.command_palette import CommandPalette
import logging
import time
import hashlib
import os
import sys
import subprocess

# Thresholds above which decompiled output is written to a file instead of
# being rendered inline in a QTextEdit (which becomes unresponsive on huge text).
MAX_DISPLAY_SIZE = 2_000_000   # bytes
MAX_DISPLAY_LINES = 50_000     # lines


def open_path_externally(path):
    """Open a file with the OS default handler, cross-platform.

    Replaces os.startfile (Windows-only). Returns True on success.
    """
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: B606 - Windows only
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
        return True
    except Exception:
        return False


from src.core.universal_loader import UniversalLoader
from src.core.disassembler import DisassemblerEngine, Architecture
from src.core.program_model import ProgramModel
from src.core.unpacker import BasicUnpacker
from src.core.decompiler_manager import DecompilerManager, DecompilerEngine
from src.core.ai_decompiler import AIDecompiler
from src.intelligence.threat_intel import ThreatIntelligence, IOCExtractor
from src.gui.advanced_viewer import AdvancedVisualizationWidget, AIAnalysisPanel
from src.gui.network_capture_panel import NetworkCapturePanel
from src.gui.full_software_panel import FullSoftwarePanel
from src.intelligence.endpoint_detector import detect_endpoints, format_endpoint_results
from src.gui.project_analysis_tab import ProjectAnalysisTab  # New import for project analysis tab
logger = logging.getLogger(__name__)

class BinaryAnalysisWorker(QThread):
    """
    Worker thread for analyzing a binary file in the background.
    Handles loading, section extraction, and disassembly for PE, ELF, and Mach-O binaries.
    """
    analysis_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)

    def __init__(self, binary_loader, disassembler, file_path):
        super().__init__()
        self.binary_loader = binary_loader
        self.disassembler = disassembler
        self.file_path = file_path

    def run(self):
        try:
            logger.debug("[DEBUG] Starting binary analysis...")
            self.progress_update.emit("Loading binary...")

            if not self.binary_loader.load(self.file_path):
                logger.error("[DEBUG] Binary loading failed")
                self.analysis_complete.emit({
                    'binary_info': {'type': 'Unknown', 'path': self.file_path},
                    'instructions': [],
                    'sections': [],
                    'file_path': self.file_path
                })
                return

            # Gather file type and section info
            file_type = getattr(self.binary_loader, 'file_type', None)
            bin_info = {'type': str(file_type), 'path': self.file_path}
            instructions = []
            sections = []

            parsed = getattr(self.binary_loader, 'parsed', None)
            if parsed is not None:
                if hasattr(parsed, 'sections'):
                    sections = [
                        {
                            'name': getattr(s, 'name', ''),
                            'size': getattr(s, 'size', 0),
                            'virtual_address': getattr(s, 'virtual_address', 0),
                            'offset': getattr(s, 'offset', 0),   # file offset (for VA mapping)
                        } for s in getattr(parsed, 'sections', [])
                    ]
                    bin_info['sections'] = sections
                elif isinstance(parsed, dict) and 'sections' in parsed:
                    sections = parsed['sections']
                    bin_info['sections'] = sections
                else:
                    bin_info['sections'] = []
            else:
                bin_info['sections'] = []

            # Disassemble if this is a supported binary type
            if file_type and str(file_type) in ['FileType.PE', 'FileType.ELF', 'FileType.MACHO'] and sections:
                arch = None
                try:
                    # Try to detect architecture using LIEF header fields
                    if parsed is not None and hasattr(parsed, 'header'):
                        header = parsed.header
                        # Mach-O carries cpu_type (critical on Apple Silicon: a thin
                        # arm64 binary must NOT be disassembled as x86).
                        if hasattr(header, 'cpu_type'):
                            ct = str(header.cpu_type).upper()
                            if 'ARM64' in ct or 'AARCH64' in ct:
                                arch = Architecture.ARM64
                            elif 'X86_64' in ct or 'AMD64' in ct:
                                arch = Architecture.X86_64
                            elif 'ARM' in ct:
                                arch = Architecture.ARM
                            elif 'X86' in ct or 'I386' in ct:
                                arch = Architecture.X86
                        if arch is None and hasattr(header, 'machine_type'):
                            machine = str(header.machine_type)
                            if 'AMD64' in machine or 'X86_64' in machine:
                                arch = Architecture.X86_64
                            elif 'AARCH64' in machine or 'ARM64' in machine:
                                arch = Architecture.ARM64
                            elif 'I386' in machine or 'X86' in machine:
                                arch = Architecture.X86
                            elif 'ARM' in machine:
                                arch = Architecture.ARM
                        elif arch is None and hasattr(header, 'arch'):
                            arch_val = str(header.arch)
                            if 'x86_64' in arch_val:
                                arch = Architecture.X86_64
                            elif 'x86' in arch_val:
                                arch = Architecture.X86
                            elif 'arm64' in arch_val:
                                arch = Architecture.ARM64
                            elif 'arm' in arch_val:
                                arch = Architecture.ARM
                    # Fallback if architecture wasn't detected above
                    if arch is None:
                        if str(file_type) in ['FileType.PE', 'FileType.ELF', 'FileType.MACHO']:
                            arch = Architecture.X86_64
                    if arch is not None:
                        self.disassembler.initialize(arch)
                        bin_info['arch'] = str(arch)
                        logger.debug(f"[DEBUG] Disassembler initialized for arch: {arch}")
                    else:
                        logger.debug("[DEBUG] Could not detect architecture, skipping disassembly.")
                except Exception as e:
                    logger.debug(f"[DEBUG] Architecture detection/init error: {e}")
                # Actually disassemble the code sections
                for section in sections:
                    if section['name'] in ['.text', '__text', 'CODE']:
                        content = None
                        if hasattr(self.binary_loader, 'get_section_content'):
                            content = self.binary_loader.get_section_content(section['name'])
                        if content:
                            instructions = self.disassembler.disassemble(
                                content,
                                section.get('virtual_address', 0)
                            )
                            if instructions:
                                logger.debug(f"[DEBUG] Example instructions: {[i['mnemonic'] for i in instructions[:10]]}")
                                logger.debug(f"[DEBUG] Generated {len(instructions)} instructions")
            # For unsupported or raw files, we skip disassembly on purpose

            # Best-effort function discovery from the parsed binary (LIEF).
            functions = []
            try:
                if parsed is not None and hasattr(parsed, 'functions'):
                    for fn in parsed.functions:
                        addr = getattr(fn, 'address', 0) or 0
                        name = getattr(fn, 'name', '') or f"sub_{addr:x}"
                        if addr:
                            functions.append({'name': name, 'address': int(addr)})
                    functions.sort(key=lambda d: d['address'])
            except Exception as fe:
                logger.error(f"[DEBUG] Function discovery failed: {fe}")

            # Imported symbol names (for the dangerous-import vuln check).
            imports = []
            try:
                if parsed is not None and hasattr(parsed, 'imported_functions'):
                    for imp in parsed.imported_functions:
                        nm = getattr(imp, 'name', None) or str(imp)
                        if nm:
                            imports.append(nm)
            except Exception:
                imports = []

            self.analysis_complete.emit({
                'binary_info': bin_info,
                'instructions': instructions,
                'sections': sections,
                'functions': functions,
                'imports': imports,
                'file_path': self.file_path
            })

        except Exception as e:
            logger.debug(f"[DEBUG] Critical error during binary analysis: {str(e)}")
            self.progress_update.emit(f"Error: {str(e)}")

class DecompileWorker(QThread):
    """
    Worker thread for running AI and traditional decompilation in the background.
    Feeds the analysis log to all registered decompiler engines and collects the results.
    """
    decompile_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)

    def __init__(self, decompiler_manager, analysis_log, file_path):
        super().__init__()
        self.decompiler_manager = decompiler_manager
        self.analysis_log = analysis_log  # Full analysis log for decompilation
        self.file_path = file_path

    def run(self):
        try:
            self.progress_update.emit("Starting AI decompilation...")
            # Run parallel decompilation with all engines, passing the full analysis log
            results = self.decompiler_manager.decompile_parallel(
                self.analysis_log,
                self.file_path
            )
            # Try to get a consensus result from all engines
            consensus = self.decompiler_manager.get_consensus_result(results)
            results['consensus'] = consensus
            self.decompile_complete.emit(results)
        except Exception as e:
            logger.error(f"[DecompileWorker] Something went wrong during decompilation: {str(e)}")
            self.progress_update.emit(f"Decompilation error: {str(e)}")


class ThreatAnalysisWorker(QThread):
    """
    Worker thread for running threat intelligence checks on the binary file.
    Computes the hash and queries the threat intelligence engine.
    """
    threat_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)

    def __init__(self, file_path, threat_intel):
        super().__init__()
        self.file_path = file_path
        self.threat_intel = threat_intel

    def run(self):
        try:
            self.progress_update.emit("Analyzing threat intelligence...")
            # Calculate the SHA-256 hash of the file for lookup
            with open(self.file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            # Query the threat intelligence engine
            threat_results = self.threat_intel.analyze_binary_hash(file_hash)
            self.threat_complete.emit({
                'hash': file_hash,
                'results': threat_results
            })
        except Exception as e:
            logger.error(f"[ThreatAnalysisWorker] Threat analysis failed: {str(e)}")
            self.progress_update.emit(f"Threat analysis error: {str(e)}")

class AIWorker(QThread):
    """Runs a (potentially slow) AI/LLM callable off the UI thread.

    Used for ask/summarize/enhance so an Ollama call never freezes the window.
    """
    result_ready = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, func, *args):
        super().__init__()
        self._func = func
        self._args = args

    def run(self):
        try:
            self.result_ready.emit(self._func(*self._args) or "")
        except Exception as e:
            self.failed.emit(str(e))

class FullDecompileWorker(QThread):
    """Full-binary decompilation off the UI thread.

    Tries AI (Ollama) -> RetDec -> Ghidra, using only backends that are
    actually available, and emits the first usable result.
    """
    result_ready = pyqtSignal(dict)   # {'code': str, 'engine': str}
    progress_update = pyqtSignal(str)

    def __init__(self, file_path, assembly, ai_decompiler, decompiler_manager):
        super().__init__()
        self.file_path = file_path
        self.assembly = assembly
        self.ai_decompiler = ai_decompiler
        self.decompiler_manager = decompiler_manager

    @staticmethod
    def _usable(text):
        return bool(text) and text.strip() and \
            'error' not in text.lower() and 'failed' not in text.lower()

    def run(self):
        from src.core import capabilities
        try:
            code, engine = None, 'None'
            if self.assembly and capabilities.tool_available('ollama'):
                self.progress_update.emit("Running AI decompilation...")
                r = self.ai_decompiler.decompile_assembly(self.assembly)
                if self._usable(r):
                    code, engine = r, 'AI (Ollama)'
            if not code and capabilities.tool_available('retdec'):
                self.progress_update.emit("Running RetDec...")
                r = self.decompiler_manager._run_retdec(self.file_path)
                if self._usable(r):
                    code, engine = r, 'RetDec'
            if not code and capabilities.tool_available('ghidra'):
                self.progress_update.emit("Running Ghidra...")
                r = self.decompiler_manager._run_ghidra(self.file_path)
                if self._usable(r):
                    code, engine = r, 'Ghidra'
            if not code:
                code = ("[ERROR] No decompiler backend is available or produced output.\n"
                        "Install Ghidra or RetDec (and add to PATH), or run Ollama "
                        "(`ollama serve`), then retry. See the Analysis Log for capabilities.")
            self.result_ready.emit({'code': code, 'engine': engine})
        except Exception as e:
            self.result_ready.emit({'code': f"[ERROR] Full decompilation failed: {e}", 'engine': 'None'})

class NetworkResolveWorker(QThread):
    """Off-thread: local IP, public DNS resolution, and LIVE socket capture."""
    done = pyqtSignal(dict, list, list)   # {host:[ips]}, [local_ips], [live_conns]

    def __init__(self, hosts, app_name=None):
        super().__init__()
        self.hosts = hosts
        self.app_name = app_name

    def run(self):
        from src.core import network_intel, live_connections
        local, resolved, live = [], {}, []
        try:
            local = network_intel.local_ips()
            resolved = network_intel.resolve_endpoints(self.hosts, limit=25, timeout=3.0)
        except Exception:
            pass
        try:
            if self.app_name:
                live = live_connections.live_connections(self.app_name)
        except Exception:
            pass
        self.done.emit(resolved, local, live)

class MainWindow(QMainWindow):
    def compose_analysis_log(self, results):
        """Compose a full analysis log string from the results dict for AI decompilation."""
        log = []
        # Binary info
        if 'binary_info' in results:
            log.append("[Binary Info]")
            for k, v in results['binary_info'].items():
                log.append(f"{k}: {v}")
            log.append("")
        # Sections
        if 'sections' in results and isinstance(results['sections'], list):
            log.append("[Sections]")
            for section in results['sections']:
                if isinstance(section, dict):
                    line = ", ".join(f"{k}: {v}" for k, v in section.items())
                    log.append(line)
                else:
                    log.append(str(section))
            log.append("")
        # Disassembly
        if 'disassembly' in results:
            log.append("[Disassembly]")
            log.append(results['disassembly'])
            log.append("")
        # Any other relevant info
        for key, value in results.items():
            if key not in ('binary_info', 'sections', 'disassembly'):
                log.append(f"[{key.capitalize()}]")
                log.append(str(value))
                log.append("")
        return "\n".join(log)

    def update_progress(self, message):
        """Update the progress bar and log view with a progress message."""
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setFormat(str(message))
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[PROGRESS] {message}")

    def start_binary_analysis(self, file_path):
        """Start background binary analysis for the selected file."""
        # Stop any in-flight analysis so two threads never disassemble concurrently
        # (they used to share one engine, producing duplicated/interleaved output).
        prev = getattr(self, 'analysis_worker', None)
        if prev is not None and prev.isRunning():
            prev.requestInterruption()
            prev.quit()
            if not prev.wait(1500):
                prev.terminate()
                prev.wait(500)
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setFormat("Analyzing binary...")
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[INFO] Starting analysis for: {file_path}")
        # Give each analysis its own loader/disassembler (no shared mutable state).
        self.analysis_worker = BinaryAnalysisWorker(
            UniversalLoader(), DisassemblerEngine(), file_path)
        self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_worker.progress_update.connect(self.update_progress)
        self.analysis_worker.start()
        # Point the live-capture panel at the loaded app.
        if hasattr(self, 'network_capture_panel'):
            self.network_capture_panel.set_target(file_path)

    def configure_misp(self):
        if hasattr(self, 'log_view'):
            self.log_view.append('[INFO] MISP configuration not implemented yet.')

    def export_iocs(self):
        """Export the extracted IOCs (from the Threat Intel panel) to a JSON file."""
        try:
            iocs = []
            if hasattr(self, 'ioc_list'):
                for i in range(self.ioc_list.topLevelItemCount()):
                    item = self.ioc_list.topLevelItem(i)
                    iocs.append({
                        'type': item.text(0),
                        'value': item.text(1),
                        'context': item.text(2),
                    })
            if not iocs:
                if hasattr(self, 'log_view'):
                    self.log_view.append("[ERROR] No IOCs available to export. Run an analysis first.")
                return
            file_path, _ = QFileDialog.getSaveFileName(self, "Export IOCs", "iocs.json", "JSON Files (*.json);;All Files (*)")
            if file_path:
                import json
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(iocs, f, indent=2)
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Exported {len(iocs)} IOC(s) to {file_path}")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[ERROR] Failed to export IOCs: {e}")

    def export_analysis(self):
        """Export the current binary analysis log to a file."""
        try:
            analysis_log = None
            if hasattr(self, 'last_analysis_results') and self.last_analysis_results is not None:
                analysis_log = self.last_analysis_results.get('analysis_log')
            if not analysis_log:
                if hasattr(self, 'log_view'):
                    self.log_view.append("[ERROR] No analysis log available to export.")
                return
            file_path, _ = QFileDialog.getSaveFileName(self, "Export Analysis Log", "analysis_log.txt", "Text Files (*.txt);;All Files (*)")
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(analysis_log)
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Exported analysis log to {file_path}")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[ERROR] Failed to export analysis log: {e}")

    def _run_ai_async(self, func, args, on_result, busy_msg="Running AI in background..."):
        """Run an AI/LLM callable off the UI thread; gate on Ollama availability."""
        from src.core import capabilities
        if not capabilities.tool_available('ollama'):
            if hasattr(self, 'log_view'):
                self.log_view.append("[WARN] Ollama not available — install it and run "
                                      "`ollama serve` to use AI features.")
            return
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[INFO] {busy_msg}")
        worker = AIWorker(func, *args)
        worker.result_ready.connect(on_result)
        if hasattr(self, 'log_view'):
            worker.failed.connect(lambda e: self.log_view.append(f"[ERROR] AI task failed: {e}"))
        # Keep a reference so the QThread is not garbage-collected mid-run.
        self._ai_workers = getattr(self, '_ai_workers', [])
        self._ai_workers.append(worker)
        worker.finished.connect(
            lambda: self._ai_workers.remove(worker) if worker in self._ai_workers else None)
        worker.start()

    def ask_ai_about_code(self):
        """Prompt the user for a question about the code and get an AI answer."""
        from PyQt6.QtWidgets import QInputDialog, QMessageBox
        code = self.source_code_view.toPlainText() if hasattr(self, 'source_code_view') else ''
        if not code.strip():
            if hasattr(self, 'log_view'):
                self.log_view.append("[ERROR] No code available for Q&A.")
            return
        question, ok = QInputDialog.getText(self, "Ask AI about Code", "Enter your question for the AI:")
        if not ok or not question.strip():
            return
        prompt = (
            "You are an expert reverse engineer. Given the following C code, answer the user's question as concisely and accurately as possible. "
            "If the question is about code behavior, security, or vulnerabilities, provide actionable insights.\n\n"
            f"C code:\n{code}\n\nQuestion: {question}\nAnswer: "
        )
        def on_result(answer):
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[INFO] AI Answer:\n{answer}")
            QMessageBox.information(self, "AI Q&A", answer)
        self._run_ai_async(self.ai_decompiler._decompile_with_ollama, (prompt,),
                           on_result, busy_msg=f"Asking AI: {question}")

    def summarize_function_with_ai(self):
        """Summarize the function currently shown in the Source Code tab using the AI decompiler."""
        code = self.source_code_view.toPlainText() if hasattr(self, 'source_code_view') else ''
        if not code.strip():
            if hasattr(self, 'log_view'):
                self.log_view.append("[ERROR] No code available to summarize.")
            return
        # Optionally prompt for function name
        from PyQt6.QtWidgets import QInputDialog
        func_name = ''
        if hasattr(self, 'log_view'):
            self.log_view.append("[INFO] Prompting user for function name to summarize (optional)...")
        func_name, ok = QInputDialog.getText(self, "Summarize Function", "Enter function name to summarize (leave blank for all):")
        if not ok:
            return
        code_to_summarize = code
        if func_name.strip():
            # Try to extract the function code by name (very simple heuristic)
            import re
            pattern = re.compile(r'(\w[\w\s\*]+\s+' + re.escape(func_name.strip()) + r'\s*\([^)]*\)\s*\{[\s\S]*?^\})', re.MULTILINE)
            match = pattern.search(code)
            if match:
                code_to_summarize = match.group(0)
            else:
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[WARN] Could not find function '{func_name.strip()}', summarizing all code.")
        prompt = (
            f"Summarize the following C code{' for the function ' + func_name.strip() if func_name.strip() else ''}. "
            "Focus on what the code does, its purpose, and any security-relevant or unusual behavior. "
            "Output a concise summary for a reverse engineer.\n\n"
            f"{code_to_summarize}\n"
        )
        from PyQt6.QtWidgets import QMessageBox
        def on_result(summary):
            if hasattr(self, 'log_view'):
                self.log_view.append("[INFO] AI Summary:\n" + summary)
            QMessageBox.information(self, "AI Function Summary", summary)
        self._run_ai_async(self.ai_decompiler._decompile_with_ollama, (prompt,),
                           on_result, busy_msg="Requesting function summary from AI...")

    def export_ai_results(self):
        """Export the current AI decompilation results from the Source Code tab to a file."""
        try:
            code = self.source_code_view.toPlainText() if hasattr(self, 'source_code_view') else ''
            if not code.strip():
                if hasattr(self, 'log_view'):
                    self.log_view.append("[ERROR] No AI decompilation results to export.")
                return
            file_path, _ = QFileDialog.getSaveFileName(self, "Export AI Decompilation Results", "ai_decompilation.c", "C Source Files (*.c);;All Files (*)")
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Exported AI decompilation results to {file_path}")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[ERROR] Failed to export AI results: {e}")

    def enhance_with_ai_comments(self):
        """Enhance the last Ghidra decompilation output with AI comments and improvements."""
        ghidra_code = None
        # Try to get the last Ghidra result from last_analysis_results
        if hasattr(self, 'last_analysis_results') and self.last_analysis_results is not None:
            ghidra_result = self.last_analysis_results.get('ghidra')
            if ghidra_result and isinstance(ghidra_result, dict):
                ghidra_code = ghidra_result.get('code')
            elif isinstance(ghidra_result, str):
                ghidra_code = ghidra_result
        # Fallback to current Source Code tab
        if not ghidra_code and hasattr(self, 'source_code_view'):
            ghidra_code = self.source_code_view.toPlainText()
        if not ghidra_code:
            if hasattr(self, 'log_view'):
                self.log_view.append("[ERROR] No Ghidra code available to enhance.")
            return
        def on_result(enhanced_code):
            if hasattr(self, 'source_code_view'):
                self.source_code_view.setPlainText(enhanced_code)
            if hasattr(self, 'log_view'):
                self.log_view.append("[INFO] Enhanced code displayed in Source Code tab.")
        self._run_ai_async(self.ai_decompiler.enhance_ghidra_output, (ghidra_code,),
                           on_result, busy_msg="Enhancing Ghidra code with AI comments...")

    def reanalyze_with_ai(self):
        """Re-run AI decompilation using the last analysis log or current disassembly view."""
        analysis_log = None
        if hasattr(self, 'last_analysis_results') and self.last_analysis_results is not None:
            analysis_log = self.last_analysis_results.get('analysis_log')
        # Prefer the structured model's assembly listing over scraping the view.
        model = getattr(self, 'program_model', None)
        if not analysis_log and model is not None and model.instructions:
            analysis_log = model.assembly_text()
        if not analysis_log and hasattr(self, 'disassembly_view'):
            analysis_log = self.disassembly_view.toPlainText()
        if not analysis_log:
            if hasattr(self, 'log_view'):
                self.log_view.append("[ERROR] No analysis log available for AI decompilation.")
            return
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
        if hasattr(self, 'log_view'):
            self.log_view.append("[INFO] Re-running AI decompilation...")
        self.decompile_worker = DecompileWorker(
            self.decompiler_manager,
            analysis_log,
            self.current_file_path
        )
        self.decompile_worker.decompile_complete.connect(self.on_decompile_complete)
        self.decompile_worker.progress_update.connect(self.update_progress)
        self.decompile_worker.start()

    def open_file(self):
        """Open a binary file, a macOS .app bundle, or a folder/archive."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "All Files (*)")
        if file_path:
            self.open_path(file_path)

    def open_path(self, file_path):
        """Route a chosen path: single binary, .app bundle, or multi-file app."""
        from src.core import bundle_analysis
        # A macOS .app bundle is a directory; analyze its main executable.
        if os.path.isdir(file_path) and file_path.rstrip('/').endswith('.app'):
            exe = bundle_analysis.resolve_app_executable(file_path)
            if exe:
                self.log_view.append(f"[INFO] {os.path.basename(file_path)} is an app bundle; "
                                     f"analyzing its executable: {os.path.basename(exe)}")
                self._also_scan_bundle(file_path)
                file_path = exe
            else:
                self.log_view.append(f"[WARN] Could not find an executable inside {file_path}; "
                                     "running whole-bundle analysis instead.")
                self._scan_bundle(file_path)
                return
        # A plain directory or an archive -> whole-application analysis.
        elif os.path.isdir(file_path) or bundle_analysis.is_archive(file_path):
            self.log_view.append(f"[INFO] {os.path.basename(file_path)} looks like a "
                                 "multi-file application; running whole-app analysis.")
            self._scan_bundle(file_path)
            return

        self.current_file_path = file_path
        if hasattr(self, 'file_label'):
            self.file_label.setText(file_path)
        self.log_view.append(f"[INFO] Opened file: {file_path}")
        self.start_binary_analysis(file_path)

    def _scan_bundle(self, path):
        """Run whole-application analysis in the Full Software tab."""
        panel = getattr(self, 'full_software_panel', None)
        if panel is None:
            self.log_view.append("[ERROR] Full Software panel unavailable.")
            return
        self.analysis_tabs.setCurrentWidget(panel)
        panel.analyze_folder(path)

    def _also_scan_bundle(self, path):
        """Kick off bundle analysis alongside single-exe analysis (best effort)."""
        try:
            panel = getattr(self, 'full_software_panel', None)
            if panel is not None:
                panel.analyze_folder(path)
        except Exception:
            pass

    def __init__(self, settings, plugin_manager):
        super().__init__()
        self.settings = settings
        self.plugin_manager = plugin_manager
        self.binary_loader = UniversalLoader()
        self.disassembler = DisassemblerEngine()
        self.current_file_path = None
        # Initialize AI components and threat intelligence BEFORE any UI logic
        self.ai_decompiler = AIDecompiler()
        self.decompiler_manager = DecompilerManager()
        self.decompiler_manager.register_engine(
            DecompilerEngine.LLM4DECOMPILE, 
            self.ai_decompiler
        )
        self.threat_intel = ThreatIntelligence()
        self.ioc_extractor = IOCExtractor()
        self._welcome_screen_shown = False
        self._main_ui_initialized = False
        self.show_welcome_screen()

    def show_welcome_screen(self):
        if self._welcome_screen_shown:
            return
        self._welcome_screen_shown = True
        outer = QWidget()
        outer_layout = QVBoxLayout(outer)
        outer_layout.addStretch()
        row = QHBoxLayout()
        row.addStretch()

        card = QFrame()
        card.setObjectName("Card")
        card.setMaximumWidth(560)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(44, 40, 44, 40)
        cl.setSpacing(12)

        brand = QLabel("⬢  RevENG")
        brand.setObjectName("Brand")
        brand.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        sub = QLabel("Reverse Engineering Platform")
        sub.setObjectName("Heading")
        sub.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        tag = QLabel("Disassembly · Decompilation · Security audit · Whole-app analysis")
        tag.setObjectName("Dim")
        tag.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        tag.setWordWrap(True)
        cl.addWidget(brand)
        cl.addWidget(sub)
        cl.addWidget(tag)
        cl.addSpacing(14)

        choose = QLabel("Choose a workspace")
        choose.setObjectName("Dim")
        cl.addWidget(choose)
        btn_cracking = QPushButton("   Cracking  —  general RE workbench")
        btn_cracking.setObjectName("Primary")
        btn_cracking.setMinimumHeight(46)
        btn_cracking.setIcon(qicon("fa5s.microchip"))
        btn_security = QPushButton("   Security  —  audit & secrets focus")
        btn_security.setMinimumHeight(46)
        btn_security.setIcon(qicon("fa5s.shield-alt"))
        cl.addWidget(btn_cracking)
        cl.addWidget(btn_security)

        row.addWidget(card)
        row.addStretch()
        outer_layout.addLayout(row)
        outer_layout.addStretch()
        self.welcome_widget = outer
        self.setCentralWidget(self.welcome_widget)
        btn_cracking.clicked.connect(self.launch_main_ui)
        btn_security.clicked.connect(self.launch_security_mode)

    def launch_main_ui(self):
        if self._main_ui_initialized:
            return
        self._main_ui_initialized = True
        self.welcome_widget.hide()
        self.init_ui()
        self.setup_menu()
        self.setup_status_bar()
        # The global theme/QSS is applied at the application level (see main.py
        # and src/gui/theme.py); no per-window stylesheet here.
        # Report detected backends and disable features whose tools are missing,
        # so nothing in the UI silently fails later.
        self.report_capabilities()
        self.apply_capability_gating()

    def report_capabilities(self):
        """Log which analysis backends are available (see src/core/capabilities)."""
        try:
            from src.core import capabilities
            if hasattr(self, 'log_view'):
                for line in capabilities.report_lines():
                    self.log_view.append(line)
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Capability probe failed: {e}")

    def apply_capability_gating(self):
        """Disable buttons/tabs whose backing tool is unavailable, with a tooltip.

        Keeps the UI honest: a disabled, explained control beats one that errors.
        """
        try:
            from src.core import capabilities
        except Exception:
            return

        def gate(widget, cap_key):
            if widget is None:
                return
            available, name, hint = capabilities.feature_status(cap_key)
            if not available:
                widget.setEnabled(False)
                widget.setToolTip(f"{name} unavailable — {hint}")

        # Full-binary decompilation needs Ghidra or RetDec.
        if not (capabilities.tool_available("ghidra") or capabilities.tool_available("retdec")):
            for attr in ("full_c_action", "cfg_btn"):
                w = getattr(self, attr, None)
                if w is not None and hasattr(w, "setEnabled"):
                    w.setToolTip("Decompiler backend unavailable — install Ghidra or RetDec (see ROADMAP/README)")
        # Network capture needs mitmproxy.
        gate(getattr(getattr(self, "network_capture_panel", None), "start_btn", None), "mitmproxy")

    def launch_security_mode(self):
        """Enter the main workbench focused on the Security Audit workflow.

        (Previously this launched a separate file-protection GUI that has been
        removed from the product; the two welcome buttons now share one workbench
        and differ only in which tab is shown first.)
        """
        self.launch_main_ui()
        # Bring the Security Audit tab to the front, if it exists.
        if hasattr(self, 'analysis_tabs'):
            for i in range(self.analysis_tabs.count()):
                if self.analysis_tabs.tabText(i) == "Security Audit":
                    self.analysis_tabs.setCurrentIndex(i)
                    break
        if hasattr(self, 'log_view'):
            self.log_view.append("[INFO] Security mode: focused on Security Audit.")

    def init_ui(self):
        self.setWindowTitle("RevENG — Reverse Engineering Platform")
        # Open to fit the available screen (never larger), centered, and allow the
        # window to shrink — the layout is responsive from here.
        self.setMinimumSize(900, 600)
        screen = self.screen()
        if screen:
            g = screen.availableGeometry()
            w = min(1440, int(g.width() * 0.94))
            h = min(900, int(g.height() * 0.94))
            self.resize(w, h)
            self.move(g.x() + (g.width() - w) // 2, g.y() + (g.height() - h) // 2)
        else:
            self.resize(1280, 820)
        self.setDockNestingEnabled(True)
        self.setDockOptions(
            QMainWindow.DockOption.AnimatedDocks | QMainWindow.DockOption.AllowNestedDocks)

        # Log view first — panels reference self.log_view if they fail to load.
        self._build_log_view()

        # Center: the analysis tab area.
        center = self.create_center_panel()
        self.setCentralWidget(center)

        # Docks: Explorer (left), Insights (right), Log (bottom). Keep widths a
        # modest fraction of the window so content never gets pushed off-screen.
        self.explorer_dock = self._add_dock(
            "Explorer", self.create_left_panel(), Qt.DockWidgetArea.LeftDockWidgetArea)
        self.insights_dock = self._add_dock(
            "Insights", self.create_right_panel(), Qt.DockWidgetArea.RightDockWidgetArea)
        self.log_dock = self._add_dock(
            "Log", self._log_dock_widget, Qt.DockWidgetArea.BottomDockWidgetArea)
        win_w = max(self.width(), 1000)
        side = max(240, min(300, int(win_w * 0.21)))
        self.resizeDocks([self.explorer_dock, self.insights_dock], [side, side],
                         Qt.Orientation.Horizontal)
        self.resizeDocks([self.log_dock], [int(self.height() * 0.2)],
                         Qt.Orientation.Vertical)

        # Far-left activity rail, top toolbar, and the ⌘K command palette.
        self._build_activity_rail()
        self._build_main_toolbar()
        self._install_command_palette()

    # ---- layout helpers -----------------------------------------------------

    def _add_dock(self, title, widget, area):
        dock = QDockWidget(title, self)
        dock.setWidget(widget)
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        self.addDockWidget(area, dock)
        return dock

    def _build_log_view(self):
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self._log_dock_widget = QWidget()
        lay = QVBoxLayout(self._log_dock_widget)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.addWidget(self.log_view)
        self.download_log_btn = QPushButton("Download Log")
        self.download_log_btn.setIcon(qicon("fa5s.download"))
        self.download_log_btn.clicked.connect(self.download_log_file)
        lay.addWidget(self.download_log_btn)

    def _build_activity_rail(self):
        rail = QToolBar("Activity")
        rail.setObjectName("ActivityRail")
        rail.setMovable(False)
        rail.setIconSize(QSize(22, 22))
        rail.setOrientation(Qt.Orientation.Vertical)
        self.addToolBar(Qt.ToolBarArea.LeftToolBarArea, rail)
        group = QActionGroup(self)
        group.setExclusive(True)

        def rail_action(ic, tip, handler, checkable=True):
            act = QAction(qicon(ic), "", self)
            act.setToolTip(tip)
            act.setCheckable(checkable)
            act.triggered.connect(handler)
            rail.addAction(act)
            if checkable:
                group.addAction(act)
            return act

        rail_action("fa5s.folder-open", "Open binary / app", self.open_file, checkable=False)
        rail.addSeparator()
        rail_action("fa5s.microchip", "Disassembly", lambda: self._select_tab("Disassembly"))
        rail_action("fa5s.code", "Source Code", lambda: self._select_tab("Source Code"))
        rail_action("fa5s.project-diagram", "Control Flow Graph", lambda: self._select_tab("CFG Viewer"))
        rail_action("fa5s.robot", "AI Decompilation", lambda: self._select_tab("AI Decompilation"))
        rail_action("fa5s.shield-alt", "Security Audit", lambda: self._select_tab("Security Audit"))
        rail_action("fa5s.key", "Key Analysis", lambda: self._select_tab("Key Analysis"))
        rail_action("fa5s.network-wired", "Network Capture", lambda: self._select_tab("Network Capture"))
        rail_action("fa5s.box-open", "Whole-app (Full Software)", lambda: self._select_tab("Full Software"))
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        rail.addWidget(spacer)
        rail_action("fa5s.terminal", "Toggle Log", lambda: self.log_dock.setVisible(not self.log_dock.isVisible()), checkable=False)
        rail_action("fa5s.cog", "Settings", lambda: (self.insights_dock.show(), self._select_right("Settings")), checkable=False)

    def _build_main_toolbar(self):
        tb = QToolBar("Main")
        tb.setObjectName("MainToolBar")
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)

        open_act = QAction(qicon("fa5s.folder-open"), "Open", self)
        open_act.triggered.connect(self.open_file)
        tb.addAction(open_act)
        re_act = QAction(qicon("fa5s.sync"), "Re-analyze", self)
        re_act.triggered.connect(self.reanalyze_current)
        tb.addAction(re_act)
        tb.addSeparator()

        cmd = QPushButton("  ⌘K  Commands")
        cmd.clicked.connect(self.open_command_palette)
        tb.addWidget(cmd)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)

        tb.addWidget(QLabel("Theme "))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(theme_mod.THEMES.keys()))
        current = self.settings.get_theme() if hasattr(self.settings, "get_theme") else theme_mod.DEFAULT_THEME
        if current in theme_mod.THEMES:
            self.theme_combo.setCurrentText(current)
        self.theme_combo.currentTextChanged.connect(self._apply_theme_choice)
        tb.addWidget(self.theme_combo)

    def _install_command_palette(self):
        sc = QShortcut(QKeySequence("Ctrl+K"), self)
        sc.activated.connect(self.open_command_palette)
        sc_mac = QShortcut(QKeySequence("Meta+K"), self)
        sc_mac.activated.connect(self.open_command_palette)

    def _select_tab(self, name):
        tabs = getattr(self, "analysis_tabs", None)
        if tabs is None:
            return
        for i in range(tabs.count()):
            if tabs.tabText(i) == name:
                tabs.setCurrentIndex(i)
                return

    def _select_right(self, name):
        tabs = getattr(self, "right_tabs", None)
        if tabs is None:
            return
        for i in range(tabs.count()):
            if tabs.tabText(i) == name:
                tabs.setCurrentIndex(i)
                return

    def reanalyze_current(self):
        if self.current_file_path:
            self.start_binary_analysis(self.current_file_path)
        elif hasattr(self, "log_view"):
            self.log_view.append("[INFO] Open a file first to re-analyze.")

    def _apply_line_spacing(self, edit, pct=145, max_blocks=40000):
        """Add comfortable line spacing to a code view (skipped on huge listings)."""
        try:
            from PyQt6.QtGui import QTextCursor, QTextBlockFormat
            if edit.document().blockCount() > max_blocks:
                return
            cur = edit.textCursor()
            cur.select(QTextCursor.SelectionType.Document)
            bf = QTextBlockFormat()
            bf.setLineHeight(pct, QTextBlockFormat.LineHeightTypes.ProportionalHeight.value)
            cur.mergeBlockFormat(bf)
            edit.moveCursor(QTextCursor.MoveOperation.Start)
        except Exception:
            pass

    def _running_workers(self):
        """Collect all QThread workers that might still be running."""
        workers = []
        for attr in ("analysis_worker", "decompile_worker", "threat_worker",
                     "_net_worker", "_full_decompile_worker"):
            w = getattr(self, attr, None)
            if w is not None:
                workers.append(w)
        workers.extend(getattr(self, "_ai_workers", []))
        for panel_attr, worker_attr in (("full_software_panel", "analysis_worker"),
                                        ("network_capture_panel", "capture_thread")):
            panel = getattr(self, panel_attr, None)
            w = getattr(panel, worker_attr, None) if panel is not None else None
            if w is not None:
                workers.append(w)
        return workers

    def closeEvent(self, event):
        """Stop background worker threads cleanly so Qt doesn't abort on exit.

        (Previously, closing while a DecompileWorker/analysis thread was running
        triggered 'QThread: Destroyed while thread is still running' -> abort.)
        """
        for w in self._running_workers():
            try:
                if hasattr(w, "isRunning") and w.isRunning():
                    if hasattr(w, "stop"):
                        w.stop()
                    w.requestInterruption()
                    w.quit()
                    if not w.wait(2500):
                        w.terminate()
                        w.wait(1000)
            except Exception:
                pass
        # Stop any live network capture (mitmdump + launched app subprocesses).
        ncp = getattr(self, "network_capture_panel", None)
        if ncp is not None and hasattr(ncp, "stop_capture"):
            try:
                ncp.stop_capture()
            except Exception:
                pass
        super().closeEvent(event)

    @staticmethod
    def _fmt_size(n):
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.0f} KB"
        return f"{n / 1024 / 1024:.1f} MB"

    def _run_endpoint_and_network_analysis(self):
        """Scan strings (and Electron JS source) for endpoints; resolve server IPs.

        For Electron apps (Discord/Slack/VS Code/...) the native file you opened is
        a stub — the real source is JavaScript in app.asar. We extract it, show it,
        and scan it for the app's REAL endpoints, then resolve them to server IPs
        and report the local machine IP.
        """
        import glob
        import tempfile
        from src.intelligence.endpoint_detector import (
            detect_endpoints, format_endpoint_results, extract_strings)
        from src.core import electron, network_intel
        self._electron_source_shown = False   # reset per analysis
        self._electron_src_dir = None
        try:
            sources = []
            if self.current_file_path and os.path.isfile(self.current_file_path):
                with open(self.current_file_path, 'rb') as fh:
                    sources.extend(extract_strings(fh.read(64 * 1024 * 1024)))

            electron_header = ""
            app = (electron.find_enclosing_app(self.current_file_path)
                   if self.current_file_path else None)
            if app and electron.is_electron_app(app):
                src_dir = tempfile.mkdtemp(prefix="re_electron_src_")
                nfiles = electron.extract_source(app, src_dir)
                self._electron_src_dir = src_dir
                for f in glob.glob(os.path.join(src_dir, "**", "*"), recursive=True):
                    if os.path.isfile(f) and f.lower().endswith(
                            (".js", ".mjs", ".cjs", ".ts", ".json", ".html", ".css")):
                        try:
                            with open(f, encoding="utf-8", errors="replace") as fh:
                                sources.append(fh.read())
                        except OSError:
                            pass
                electron_header = (
                    f"[ELECTRON APP] {os.path.basename(app)} is a JavaScript (Electron) app.\n"
                    f"Real source extracted from app.asar: {nfiles} file(s) -> {src_dir}\n"
                    "Endpoints below include the app's real JS source, not just the native stub.\n\n")
                self._show_electron_source(app, src_dir, nfiles)
                if hasattr(self, 'log_view'):
                    self.log_view.append(
                        f"[ELECTRON] {os.path.basename(app)}: extracted {nfiles} real "
                        f"source files to {src_dir}")

            endpoints = detect_endpoints(sources)
            self._last_endpoint_count = len(endpoints)
            self._last_endpoints = endpoints   # kept for evidence-ranking once live data lands
            self.endpoint_detection_view.setPlainText(
                electron_header + format_endpoint_results(endpoints))

            # Server IPs come from URL hosts (reliable) — not the bare-domain dump,
            # which on minified bundles can include embedded data lists.
            urls = [e.content for e in endpoints if e.category == 'URL']
            hosts = network_intel.hosts_from_urls(urls)

            # Claim 4 evidence: flag known third-party trackers among the endpoints,
            # and hand the static host set to the live-capture panel for static↔live
            # correlation (a host found here AND seen live is proof it's really used).
            try:
                from src.core import tracker_list
                self._static_hosts = hosts
                self.endpoint_detection_view.append("\n\n" + tracker_list.summarize(hosts))
                if hasattr(self, 'network_capture_panel'):
                    self.network_capture_panel.set_static_hosts(hosts)
            except Exception:
                pass
            # App name for LIVE socket capture: the .app bundle name, else exe name.
            from src.core import electron as _el
            app_bundle = (_el.find_enclosing_app(self.current_file_path)
                          if self.current_file_path else None)
            if app_bundle:
                self._app_name = os.path.basename(app_bundle)[:-4]  # strip ".app"
            elif self.current_file_path:
                self._app_name = os.path.basename(self.current_file_path)
            else:
                self._app_name = None
            self.endpoint_detection_view.append(
                "\n[Capturing LIVE connections + resolving DNS in background…]")
            self._net_worker = NetworkResolveWorker(hosts, app_name=self._app_name)
            self._net_worker.done.connect(self._on_network_resolved)
            self._net_worker.start()
        except Exception as e:
            self.endpoint_detection_view.setPlainText(f"[ERROR] Endpoint detection failed: {e}")
            self._last_endpoint_count = 0

    def _on_network_resolved(self, resolved, local, live):
        from src.core import network_intel, live_connections
        app_name = getattr(self, '_app_name', None) or "the app"

        # Evidence-based ranking: fold the LIVE socket signal + DNS resolution into
        # the static endpoints so the view leads with what the app ACTUALLY uses and
        # collapses the library/namespace/PKI noise (Task 1). Live IPs/PTR hosts come
        # from the socket table; resolved is the DNS map for the static hosts.
        live_ips, live_hosts = [], []
        for c in (live or []):
            raddr = c.get("raddr", "")
            ip = raddr.rsplit(":", 1)[0] if raddr else ""
            if ip:
                live_ips.append(ip)
            if c.get("rdns"):
                live_hosts.append(c["rdns"])
        try:
            from src.core import endpoint_rank
            ranked = endpoint_rank.rank(
                getattr(self, "_last_endpoints", []) or [],
                live_hosts=live_hosts, live_ips=live_ips, resolved=resolved)
            counts = endpoint_rank.summarize_counts(ranked)
            self._last_real_endpoint_count = sum(
                counts.get(t, 0) for t in ("confirmed-live", "live-only", "real-server"))
            ranked_block = (endpoint_rank.format_ranked(ranked)
                            + "\n\n" + "=" * 60 + "\n"
                            + "RAW DETECTION + RESOLUTION DETAIL (below)\n")
            # Lead with the ranked intelligence, keep the raw detail beneath it.
            prior = self.endpoint_detection_view.toPlainText()
            self.endpoint_detection_view.setPlainText(ranked_block + "\n" + prior)
        except Exception as e:
            self._last_real_endpoint_count = 0
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Endpoint ranking failed: {e}")

        # LIVE capture detail — the real, non-googleable signal.
        block = ("\n" + "=" * 60 + "\n"
                 + live_connections.format_live_connections(app_name, live)
                 + "\n\n" + network_intel.format_network_intel(local, resolved))
        self.endpoint_detection_view.append(block)
        if hasattr(self, 'insights_panel'):
            real = getattr(self, '_last_real_endpoint_count', 0)
            self.insights_panel.update_field(
                'endpoints', f"{real} real / {self._last_endpoint_count} found  ·  {len(live)} live")

    def _show_electron_source(self, app, src_dir, nfiles):
        """Show the extracted real JS source in the Source Code tab."""
        import glob
        files = [f for f in glob.glob(os.path.join(src_dir, "**", "*"), recursive=True)
                 if os.path.isfile(f)]
        jsfiles = sorted((f for f in files if f.lower().endswith((".js", ".mjs", ".cjs"))),
                         key=lambda f: -os.path.getsize(f))
        header = (f"// ELECTRON APP — REAL JAVASCRIPT SOURCE\n"
                  f"// {os.path.basename(app)} is an Electron app; this is its ACTUAL source\n"
                  f"// (extracted from app.asar, not decompiled).\n"
                  f"// {nfiles} files extracted to: {src_dir}\n//\n// Files:\n")
        listing = "\n".join(f"//   {os.path.relpath(f, src_dir)}  ({os.path.getsize(f):,} B)"
                            for f in files)
        body = ""
        if jsfiles:
            main = jsfiles[0]
            text = ""
            try:
                with open(main, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(600_000)   # inline preview; full file is on disk
            except OSError:
                text = ""
            # Beautify minified JS if jsbeautifier is available (optional).
            try:
                import jsbeautifier
                text = jsbeautifier.beautify(text)
            except Exception:
                pass
            body = (f"\n\n// ===== {os.path.relpath(main, src_dir)} "
                    f"(largest JS, first 600 KB shown — full file at {src_dir}) =====\n"
                    + text)
        self.source_code_view.setPlainText(header + listing + body)
        self._electron_source_shown = True   # AI must not overwrite this real source

    def _update_insights(self, results):
        """Populate the right-dock Insights panel + status bar from results."""
        info = results.get('binary_info', {}) or {}
        fmt = str(info.get('type', '—')).replace('FileType.', '')
        arch = str(info.get('arch', '—')).replace('Architecture.', '')
        size = '—'
        secrets = '—'
        try:
            if self.current_file_path and os.path.isfile(self.current_file_path):
                size = self._fmt_size(os.path.getsize(self.current_file_path))
                from src.core.bundle_analysis import _SECRET_RE
                with open(self.current_file_path, 'rb') as f:
                    secrets = len(_SECRET_RE.findall(f.read(4 * 1024 * 1024)))
        except Exception:
            pass
        funcs = len(results.get('functions', []))
        secs = len(results.get('sections', []))
        instr = blocks = 0
        model = getattr(self, 'program_model', None)
        if model is not None and model.instructions:
            st = model.stats()
            instr, blocks = st['instructions'], st['basic_blocks']
        endpoints = getattr(self, '_last_endpoint_count', 0)
        protection = getattr(self, '_last_protection_level', 'none')

        if hasattr(self, 'insights_panel'):
            self.insights_panel.update_from(
                format=fmt, arch=arch, size=size, functions=funcs, sections=secs,
                instructions=instr, blocks=blocks, secrets=secrets,
                endpoints=endpoints, protection=protection)
        if hasattr(self, 'status_format'):
            self.status_format.setText(fmt)
            self.status_arch.setText(arch)
            self.status_size.setText(size)
        if hasattr(self, 'file_label') and self.current_file_path:
            self.file_label.setText(os.path.basename(self.current_file_path))

    def _apply_theme_choice(self, name):
        app = QApplication.instance()
        if app is not None:
            theme_mod.apply_theme(app, name)
        if hasattr(self.settings, "set_theme"):
            self.settings.set_theme(name)
        if hasattr(self, "log_view"):
            self.log_view.append(f"[INFO] Theme set to {name}.")

    def open_command_palette(self):
        actions = [
            ("Open binary / app…", self.open_file),
            ("Re-analyze current file", self.reanalyze_current),
            ("Full binary decompilation", self.run_full_decompilation),
            ("Re-analyze with AI", self.reanalyze_with_ai),
            ("Show: Disassembly", lambda: self._select_tab("Disassembly")),
            ("Show: Source Code", lambda: self._select_tab("Source Code")),
            ("Show: Control Flow Graph", lambda: self._select_tab("CFG Viewer")),
            ("Show: AI Decompilation", lambda: self._select_tab("AI Decompilation")),
            ("Show: Security Audit", lambda: self._select_tab("Security Audit")),
            ("Show: Network Capture", lambda: self._select_tab("Network Capture")),
            ("Show: Whole-app analysis", lambda: self._select_tab("Full Software")),
            ("Export IOCs", self.export_iocs),
            ("Export analysis", self.export_analysis),
            ("Toggle Log panel", lambda: self.log_dock.setVisible(not self.log_dock.isVisible())),
        ]
        for tname in theme_mod.THEMES:
            actions.append((f"Theme: {tname}", lambda n=tname: (self.theme_combo.setCurrentText(n))))
        palette = CommandPalette(actions, self)
        palette.move(self.geometry().center().x() - 260, self.geometry().top() + 120)
        palette.exec()

    def download_log_file(self):
        """Download the contents of the log view to a file chosen by the user."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Log File", f"log_{time.strftime('%Y%m%d_%H%M%S')}.txt", "Text Files (*.txt)")
            if file_path:
                log_text = self.log_view.toPlainText()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(log_text)
                self.log_view.append(f"[INFO] Log file saved to {file_path}")
                # Try to open the file automatically for user
                try:
                    open_path_externally(file_path)
                except Exception:
                    pass
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to save log file: {e}")

    def download_disassembly(self):
        """Download the disassembly output to a file chosen by the user."""
        try:
            disassembly_text = self.disassembly_view.toPlainText()
            if not disassembly_text.strip():
                if hasattr(self, 'log_view'):
                    self.log_view.append("[ERROR] No disassembly available to export.")
                return
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Disassembly", f"disassembly_{time.strftime('%Y%m%d_%H%M%S')}.txt", "Text Files (*.txt);;All Files (*)")
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(disassembly_text)
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Disassembly exported to {file_path}")
                try:
                    open_path_externally(file_path)
                except Exception:
                    pass
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[ERROR] Failed to export disassembly: {e}")

    def create_center_panel(self):
        center_widget = QWidget()
        layout = QVBoxLayout(center_widget)
        layout.setContentsMargins(8, 8, 8, 8)

        self.analysis_tabs = QTabWidget()
        self.analysis_tabs.setDocumentMode(True)
        self.analysis_tabs.setMovable(True)
        # Many tabs: scroll instead of squishing/eliding labels to "Dis...".
        self.analysis_tabs.setUsesScrollButtons(True)
        self.analysis_tabs.setElideMode(Qt.TextElideMode.ElideNone)
        self.analysis_tabs.tabBar().setExpanding(False)

        def add_tab(widget, label, ic=None):
            idx = self.analysis_tabs.addTab(widget, label)
            if ic:
                self.analysis_tabs.setTabIcon(idx, qicon(ic))
            return idx

        # Disassembly view (fonts come from the global theme QSS — no per-widget
        # Consolas/Segoe overrides that break on macOS).
        self._disassembly_tab = QWidget()
        disassembly_layout = QVBoxLayout(self._disassembly_tab)
        self.disassembly_view = QTextEdit()
        self.disassembly_view.setReadOnly(True)
        disassembly_layout.addWidget(self.disassembly_view)
        self.download_disassembly_btn = QPushButton("Download Disassembly")
        self.download_disassembly_btn.setIcon(qicon("fa5s.download"))
        self.download_disassembly_btn.clicked.connect(self.download_disassembly)
        disassembly_layout.addWidget(self.download_disassembly_btn)
        add_tab(self._disassembly_tab, "Disassembly", "fa5s.microchip")

        self.endpoint_detection_view = QTextEdit()
        self.endpoint_detection_view.setReadOnly(True)
        add_tab(self.endpoint_detection_view, "Endpoint Detection", "fa5s.network-wired")

        self.source_code_view = QTextEdit()
        self.source_code_view.setReadOnly(True)
        add_tab(self.source_code_view, "Source Code", "fa5s.code")

        from src.gui.pseudocode_toggle_widget import PseudocodeToggleWidget
        self.pseudocode_tab_widget = QWidget()
        pseudo_layout = QVBoxLayout(self.pseudocode_tab_widget)
        self.pseudocode_toggle = PseudocodeToggleWidget()
        pseudo_layout.addWidget(self.pseudocode_toggle)
        self.pseudocode_view = QTextEdit()
        self.pseudocode_view.setReadOnly(True)
        pseudo_layout.addWidget(self.pseudocode_view)
        add_tab(self.pseudocode_tab_widget, "Pseudocode", "fa5s.file-code")
        self.pseudocode_toggle.toggle_changed.connect(self.update_pseudocode_tab)

        self.ai_analysis_panel = AIAnalysisPanel()
        add_tab(self.ai_analysis_panel, "AI Decompilation", "fa5s.robot")
        self.ai_analysis_panel.reanalyze_btn.clicked.connect(self.reanalyze_with_ai)
        self.ai_analysis_panel.enhance_btn.clicked.connect(self.enhance_with_ai_comments)
        self.ai_analysis_panel.export_btn.clicked.connect(self.export_ai_results)
        self.ai_analysis_panel.summarize_btn.clicked.connect(self.summarize_function_with_ai)
        self.ai_analysis_panel.qa_btn.clicked.connect(self.ask_ai_about_code)

        self.viz_widget = AdvancedVisualizationWidget()
        add_tab(self.viz_widget, "Visualization", "fa5s.chart-area")

        self.cfg_btn = QPushButton("Show Control Flow Graph (CFG)")
        self.cfg_btn.setObjectName("Primary")
        self.cfg_btn.clicked.connect(self.show_cfg_viewer)
        cfg_holder = QWidget()
        cfg_layout = QVBoxLayout(cfg_holder)
        cfg_layout.addStretch()
        cfg_layout.addWidget(self.cfg_btn)
        cfg_layout.addStretch()
        add_tab(cfg_holder, "CFG Viewer", "fa5s.project-diagram")

        try:
            from src.gui.full_software_panel import FullSoftwarePanel
            self.full_software_panel = FullSoftwarePanel()
            add_tab(self.full_software_panel, "Full Software", "fa5s.box-open")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Full Software panel: {e}")

        try:
            from src.gui.crypto_tools_panel import CryptoToolsPanel
            self.crypto_tools_panel = CryptoToolsPanel()
            add_tab(self.crypto_tools_panel, "Crypto Tools", "fa5s.lock")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Crypto Tools panel: {e}")

        try:
            from src.gui.key_analysis_panel import KeyAnalysisPanel
            self.key_analysis_panel = KeyAnalysisPanel()
            add_tab(self.key_analysis_panel, "Key Analysis", "fa5s.key")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Key Analysis panel: {e}")

        try:
            from src.gui.security_audit_panel import SecurityAuditPanel
            self.security_audit_panel = SecurityAuditPanel()
            self.security_audit_panel.navigate_requested.connect(self.navigate_to_address)
            add_tab(self.security_audit_panel, "Security Audit", "fa5s.shield-alt")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Security Audit panel: {e}")

        try:
            from src.gui.network_capture_panel import NetworkCapturePanel
            self.network_capture_panel = NetworkCapturePanel()
            add_tab(self.network_capture_panel, "Network Capture", "fa5s.wifi")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Network Capture panel: {e}")

        try:
            from src.gui.privesc_panel import PrivescPanel
            self.privesc_panel = PrivescPanel()
            add_tab(self.privesc_panel, "Privesc Surface", "fa5s.user-shield")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Privesc panel: {e}")

        try:
            from src.gui.threat_lab_panel import ThreatLabPanel
            self.threat_lab_panel = ThreatLabPanel()
            add_tab(self.threat_lab_panel, "Threats", "fa5s.biohazard")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Threat Lab panel: {e}")

        try:
            from src.gui.runtime_crypto_panel import RuntimeCryptoPanel
            self.runtime_crypto_panel = RuntimeCryptoPanel()
            add_tab(self.runtime_crypto_panel, "Runtime Crypto", "fa5s.unlock-alt")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Runtime Crypto panel: {e}")

        self.project_analysis_tab = ProjectAnalysisTab()
        add_tab(self.project_analysis_tab, "Project Analysis", "fa5s.folder-tree")

        # Auto-start live capture when the user opens the Network Capture tab with an
        # app armed — no manual start/stop, no ports. (Launching the app is the only
        # outward action; for an already-running app the panel asks before relaunch.)
        self.analysis_tabs.currentChanged.connect(self._on_center_tab_changed)

        layout.addWidget(self.analysis_tabs)
        return center_widget

    def _on_center_tab_changed(self, index):
        try:
            ncp = getattr(self, "network_capture_panel", None)
            if ncp is None:
                return
            if self.analysis_tabs.widget(index) is ncp:
                # Arm from the loaded file if not already set, then auto-start.
                if not ncp.target_edit.text().strip() and getattr(self, "current_file_path", None):
                    ncp.set_target(self.current_file_path)
                if ncp._proxy_proc is None and ncp.target_edit.text().strip():
                    ncp.auto_start()
        except Exception as e:
            if hasattr(self, "log_view"):
                self.log_view.append(f"[WARN] auto-capture: {e}")

    def on_model_changed(self):
        """Handle AI model selection change from the combo box (Ollama only)."""
        # Only Ollama is supported, so just re-instantiate for future extensibility
        self.ai_decompiler = AIDecompiler()
        self.decompiler_manager.register_engine(
            DecompilerEngine.LLM4DECOMPILE,
            self.ai_decompiler
        )
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[INFO] Switched AI model to: Ollama (Local)")

    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_format = QLabel("—")
        self.status_arch = QLabel("—")
        self.status_size = QLabel("—")
        self.analysis_status = QLabel("Ready")
        for w in (self.status_format, self.status_arch, self.status_size, self.analysis_status):
            self.status_bar.addPermanentWidget(w)

    def create_right_panel(self):
        right_widget = QWidget()
        layout = QVBoxLayout(right_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        self.right_tabs = QTabWidget()
        self.right_tabs.setDocumentMode(True)
        self.right_tabs.setUsesScrollButtons(True)
        self.right_tabs.setElideMode(Qt.TextElideMode.ElideNone)
        self.right_tabs.tabBar().setExpanding(False)

        # Insights summary.
        self.insights_panel = InsightsPanel()
        self.insights_panel.reanalyze_requested.connect(self.reanalyze_current)
        self.right_tabs.addTab(self.insights_panel, "Insights")

        # Threat Intelligence.
        threat_widget = QWidget()
        threat_layout = QVBoxLayout(threat_widget)
        threat_layout.setContentsMargins(12, 12, 12, 12)
        lbl = QLabel("Threat Intelligence")
        lbl.setObjectName("Heading")
        threat_layout.addWidget(lbl)
        self.threat_results_view = QTextEdit()
        self.threat_results_view.setReadOnly(True)
        threat_layout.addWidget(self.threat_results_view)
        iocs_lbl = QLabel("Extracted IOCs")
        iocs_lbl.setObjectName("Dim")
        threat_layout.addWidget(iocs_lbl)
        self.ioc_list = QTreeWidget()
        self.ioc_list.setHeaderLabels(["Type", "Value", "Context"])
        threat_layout.addWidget(self.ioc_list)
        self.right_tabs.addTab(threat_widget, "Threat")

        # Settings.
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        settings_layout.setContentsMargins(12, 12, 12, 12)
        settings_layout.setSpacing(8)
        head = QLabel("Settings")
        head.setObjectName("Heading")
        settings_layout.addWidget(head)
        settings_layout.addWidget(QLabel("Theme"))
        self.theme_combo_settings = QComboBox()
        self.theme_combo_settings.addItems(list(theme_mod.THEMES.keys()))
        _cur_theme = self.settings.get_theme() if hasattr(self.settings, "get_theme") else theme_mod.DEFAULT_THEME
        if _cur_theme in theme_mod.THEMES:
            self.theme_combo_settings.setCurrentText(_cur_theme)
        self.theme_combo_settings.currentTextChanged.connect(self._apply_theme_choice)
        settings_layout.addWidget(self.theme_combo_settings)
        settings_layout.addWidget(QLabel("AI Model"))
        self.model_combo = QComboBox()
        self.model_combo.addItems(["Ollama (Local)"])
        self.model_combo.currentIndexChanged.connect(self.on_model_changed)
        settings_layout.addWidget(self.model_combo)
        settings_layout.addWidget(QLabel("OpenAI API Key"))
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("Enter your OpenAI API key here")
        settings_layout.addWidget(self.api_key_edit)
        self.entropy_cb = QCheckBox("Show Entropy Analysis")
        self.entropy_cb.setChecked(True)
        settings_layout.addWidget(self.entropy_cb)
        settings_layout.addStretch()
        self.right_tabs.addTab(settings_widget, "Settings")

        layout.addWidget(self.right_tabs)
        return right_widget

    def create_left_panel(self):
        left_widget = QWidget()
        layout = QVBoxLayout(left_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.open_btn = QPushButton("  Open Binary / App")
        self.open_btn.setObjectName("Primary")
        self.open_btn.setIcon(qicon("fa5s.folder-open"))
        self.open_btn.clicked.connect(self.open_file)
        layout.addWidget(self.open_btn)

        self.file_label = QLabel("No file loaded")
        self.file_label.setObjectName("Dim")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)

        # Analysis options.
        self.ai_decompile_cb = QCheckBox("AI decompilation")
        self.ai_decompile_cb.setChecked(True)
        self.threat_intel_cb = QCheckBox("Threat intelligence")
        self.threat_intel_cb.setChecked(True)
        self.collaboration_cb = QCheckBox("Collaboration")
        for cb in (self.ai_decompile_cb, self.threat_intel_cb, self.collaboration_cb):
            layout.addWidget(cb)

        sec_lbl = QLabel("SECTIONS")
        sec_lbl.setObjectName("Dim")
        layout.addWidget(sec_lbl)
        self.binary_info_tree = QTreeWidget()
        self.binary_info_tree.setHeaderLabels(["Section", "Address", "Size"])
        layout.addWidget(self.binary_info_tree)

        fn_lbl = QLabel("FUNCTIONS  (double-click to navigate)")
        fn_lbl.setObjectName("Dim")
        layout.addWidget(fn_lbl)
        self.functions_tree = QTreeWidget()
        self.functions_tree.setHeaderLabels(["Function", "Address"])
        self.functions_tree.itemDoubleClicked.connect(self.on_function_selected)
        layout.addWidget(self.functions_tree)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        return left_widget

    def on_function_selected(self, item, _column=0):
        """Scroll the Disassembly view to the selected function's address."""
        try:
            addr_text = item.text(1)
            addr = int(addr_text, 16)
            from PyQt6.QtGui import QTextCursor
            doc = self.disassembly_view
            # Disassembly lines start with the 8-hex address; find that line.
            target = f"{addr:08x}:"
            text = doc.toPlainText()
            idx = text.find(target)
            if idx < 0:
                # Try without zero-padding width assumption.
                target2 = f"{addr:x}:"
                idx = text.find(target2)
            if idx >= 0:
                cursor = doc.textCursor()
                cursor.setPosition(idx)
                doc.setTextCursor(cursor)
                doc.ensureCursorVisible()
                self.analysis_tabs.setCurrentWidget(self._disassembly_tab)
            else:
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Address {addr_text} not in the disassembled range.")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Could not navigate to function: {e}")

    def navigate_to_address(self, addr):
        """Jump the Disassembly view to a virtual address (used by Security Audit)."""
        try:
            addr = int(addr)
            doc = self.disassembly_view
            text = doc.toPlainText()
            idx = text.find(f"{addr:08x}:")
            if idx < 0:
                idx = text.find(f"{addr:x}:")
            if idx >= 0:
                cursor = doc.textCursor()
                cursor.setPosition(idx)
                doc.setTextCursor(cursor)
                doc.ensureCursorVisible()
                self.analysis_tabs.setCurrentWidget(self._disassembly_tab)
            elif hasattr(self, 'log_view'):
                self.log_view.append(f"[INFO] 0x{addr:x} not in the disassembled range.")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Navigate failed: {e}")

    def show_cfg_viewer(self):
        """Show the control flow graph for the current disassembly."""
        try:
            from src.gui.cfg_viewer import CFGViewer
            # Prefer the structured program model (real addresses + branch edges).
            instructions = []
            model = getattr(self, 'program_model', None)
            if model is not None and model.instructions:
                instructions = model.instructions
            elif hasattr(self.disassembly_view, 'table'):
                # Fallback: reconstruct from the disassembly table.
                table = self.disassembly_view.table
                for row in range(table.rowCount()):
                    address_item = table.item(row, 0)
                    mnemonic_item = table.item(row, 2)
                    operands_item = table.item(row, 3)
                    if address_item and mnemonic_item and operands_item:
                        try:
                            address = int(address_item.text(), 16)
                        except Exception:
                            address = row
                        instructions.append({
                            'address': address,
                            'mnemonic': mnemonic_item.text(),
                            'op_str': operands_item.text(),
                        })
            if not instructions:
                self.log_view.append("[WARN] No instructions to visualize for CFG.")
                return
            self.cfg_viewer = CFGViewer(instructions)
            self.cfg_viewer.setWindowTitle("Control Flow Graph (CFG)")
            self.cfg_viewer.show()
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to show CFG: {e}")

    def update_pseudocode_tab(self):
        """Refresh the pseudocode tab using offline or AI pseudocode based on toggle."""
        try:
            if hasattr(self, 'pseudocode_toggle') and self.pseudocode_toggle.toggle.isChecked():
                # AI pseudocode (runs in the background; never blocks the UI).
                from src.core.ai_decompiler import AIDecompiler
                # Prefer the structured model's listing, else disassemble on demand.
                assembly_code = ""
                model = getattr(self, 'program_model', None)
                if model is not None and model.instructions:
                    assembly_code = model.assembly_text()
                elif self.current_file_path:
                    from src.core.multiarch_disassembler import MultiArchDisassembler
                    mad = MultiArchDisassembler(self.current_file_path)
                    mad.load()
                    instructions = getattr(mad, 'instructions', None) or []
                    assembly_code = "\n".join(
                        f"{i['mnemonic']} {i['op_str']}".strip() for i in instructions)
                if not assembly_code.strip():
                    self.pseudocode_view.setPlainText("[ERROR] No instructions for AI pseudocode. Load a binary first.")
                    return
                ai_decompiler = getattr(self, 'ai_decompiler', None) or AIDecompiler()
                self.pseudocode_view.setPlainText("[INFO] Generating AI pseudocode in background...")
                self._run_ai_async(ai_decompiler.decompile_assembly, (assembly_code,),
                                   lambda p: self.pseudocode_view.setPlainText(p),
                                   busy_msg="Generating AI pseudocode...")
            else:
                # Offline pseudocode
                from src.core.multiarch_disassembler import MultiArchDisassembler
                mad = MultiArchDisassembler(self.current_file_path)
                mad.load()
                pseudo = mad.to_pseudocode()
                self.pseudocode_view.setPlainText(pseudo)
        except Exception as e:
            self.pseudocode_view.setPlainText(f"[ERROR] Could not generate pseudocode: {e}")

    def run_full_decompilation(self):
        """Full-binary decompilation (AI -> RetDec -> Ghidra), off the UI thread."""
        if not self.current_file_path:
            self.source_code_view.setPlainText("[ERROR] No file loaded for decompilation.")
            return
        # Prefer the already-built structured model's assembly listing.
        model = getattr(self, 'program_model', None)
        assembly = model.assembly_text() if (model and model.instructions) else ""
        self.source_code_view.setPlainText(
            "[INFO] Running full decompilation in the background...\n"
            "(This may take a while for large binaries.)")
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
        self._full_decompile_worker = FullDecompileWorker(
            self.current_file_path, assembly, self.ai_decompiler, self.decompiler_manager)
        self._full_decompile_worker.result_ready.connect(self._on_full_decompile_result)
        self._full_decompile_worker.progress_update.connect(self.update_progress)
        self._full_decompile_worker.start()

    def _on_full_decompile_result(self, res):
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(False)
        code = res.get('code', '')
        engine = res.get('engine', 'None')
        # Very large output is written to a temp file rather than rendered inline.
        if len(code.encode('utf-8')) > MAX_DISPLAY_SIZE or code.count('\n') > MAX_DISPLAY_LINES:
            import tempfile
            output_path = os.path.join(tempfile.gettempdir(), "output_full_decompile.c")
            try:
                with open(output_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(code)
                self.source_code_view.setPlainText(
                    f"[INFO] Decompiled code too large to display. Saved to {output_path}.")
                self.log_view.append(f"[INFO] Decompiled code saved to {output_path}.")
                self.show_open_output_button(output_path)
                open_path_externally(output_path)
            except Exception as e:
                self.source_code_view.setPlainText(code[:MAX_DISPLAY_SIZE])
                self.log_view.append(f"[WARN] Could not save large output: {e}")
        else:
            self.source_code_view.setPlainText(code)
        if engine and engine != 'None':
            self.log_view.append(f"[INFO] Full decompilation complete via {engine}.")
        else:
            self.log_view.append("[WARN] Full decompilation produced no usable output.")

    def on_decompile_complete(self, results):
        """AI/engine decompilation finished.

        AI (Ollama) output goes ONLY to the AI Decompilation tab. The Source Code
        tab is reserved for REAL source: Ghidra/RetDec C, or extracted Electron JS.
        We never overwrite it with hallucinated AI output.
        """
        try:
            self.ai_analysis_panel.update_analysis_results(results)
        except Exception:
            pass
        if hasattr(self, "progress_bar"):
            self.progress_bar.setVisible(False)

        def _good(r):
            c = r.get("code", "") if isinstance(r, dict) else ""
            return bool(c) and "error" not in c.lower() and "failed" not in c.lower()

        ghidra = results.get("ghidra", {}) or {}
        retdec = results.get("retdec", {}) or {}
        code, engine = None, None
        if _good(ghidra):
            code, engine = ghidra["code"], "Ghidra"
        elif _good(retdec):
            code, engine = retdec["code"], "RetDec"

        # Only put REAL decompiler output in Source Code, and never clobber the
        # extracted Electron JS source that is already shown there.
        if code and not getattr(self, "_electron_source_shown", False):
            self.source_code_view.setPlainText(code)
            if hasattr(self, "log_view"):
                self.log_view.append(f"[INFO] Source Code tab: {engine} C decompilation.")
        elif hasattr(self, "log_view"):
            self.log_view.append("[INFO] AI decompilation is in the AI Decompilation tab "
                                 "(Source Code keeps real decompiler / Electron source).")

    def setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        open_action = QAction("Open Binary", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        export_action = QAction("Export Analysis", self)
        export_action.triggered.connect(self.export_analysis)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        file_menu.addAction("Exit").triggered.connect(self.close)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")
        reanalyze_action = QAction("Re-analyze with AI", self)
        reanalyze_action.triggered.connect(self.reanalyze_with_ai)
        analysis_menu.addAction(reanalyze_action)
        
        # Add a menu action for full binary C decompilation
        full_c_action = QAction("Full Binary C Decompilation (RetDec/Ghidra)", self)
        full_c_action.triggered.connect(self.run_full_decompilation)
        analysis_menu.addAction(full_c_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Configure MISP").triggered.connect(self.configure_misp)
        tools_menu.addAction("Export IOCs").triggered.connect(self.export_iocs)

    def on_analysis_complete(self, results):
        """
        Update the UI with binary analysis results.
        """
        self.progress_bar.setVisible(False)
        instructions = results.get('instructions', [])
        sections = results.get('sections', [])

        # Populate the left-panel sections tree.
        if hasattr(self, 'binary_info_tree'):
            self.binary_info_tree.clear()
            for s in sections:
                QTreeWidgetItem(self.binary_info_tree, [
                    str(s.get('name', '')),
                    hex(s.get('virtual_address', 0)),
                    str(s.get('size', 0)),
                ])

        # Populate the left-panel functions list (double-click navigates).
        functions = results.get('functions', [])
        if hasattr(self, 'functions_tree'):
            self.functions_tree.clear()
            for fn in functions:
                QTreeWidgetItem(self.functions_tree, [
                    str(fn.get('name', '')),
                    f"{fn.get('address', 0):08x}",
                ])
            if hasattr(self, 'log_view') and functions:
                self.log_view.append(f"[INFO] Discovered {len(functions)} functions.")

        # Protection / packer report (and offer automated unpacking for UPX).
        if self.current_file_path and os.path.isfile(self.current_file_path):
            try:
                from src.core import protection_detector
                rep = protection_detector.detect_protections(self.current_file_path)
                self._last_protection_level = rep.get('level', 'none')
                if hasattr(self, 'log_view'):
                    self.log_view.append("[PROTECTION] " +
                                         protection_detector.render_protection_report(rep)
                                         .replace("\n", "\n[PROTECTION] "))
                if rep.get('automatable'):
                    unpacked = protection_detector.auto_unpack(self.current_file_path)
                    if unpacked and hasattr(self, 'log_view'):
                        self.log_view.append(f"[PROTECTION] Auto-unpacked to {unpacked}. "
                                             "Open that file to analyze the unpacked code.")
            except Exception as e:
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[WARN] Protection scan failed: {e}")

        # Only warn about packing when there is actual evidence (UPX sections or
        # very high section entropy) — not on every file.
        packed = any('upx' in str(s.get('name', '')).lower() for s in sections)
        if packed and hasattr(self, 'log_view'):
            self.log_view.append("[WARNING] Binary looks packed (UPX section found). "
                                 "Unpack with 'upx -d <file>' for better decompilation.")
            try:
                from src.core.ai_decompiler import AIDecompiler
                binary_path = getattr(self, 'current_file_path', None)
                unpacked_path = AIDecompiler.auto_unpack_upx(binary_path) if binary_path else None
                if unpacked_path:
                    self.log_view.append(f"[INFO] Auto-unpacked to {unpacked_path}. Re-run analysis on it.")
            except Exception:
                pass

        # Show plain disassembly in the format 'address: mnemonic operands'
        disasm_lines = []
        for instr in instructions:
            addr = f"{instr['address']:08x}"
            line = f"{addr}: {instr['mnemonic']}"
            if instr['op_str']:
                line += f" {instr['op_str']}"
            disasm_lines.append(line)
        self.disassembly_view.setPlainText('\n'.join(disasm_lines))
        self._apply_line_spacing(self.disassembly_view)

        # --- Endpoint Detection + Electron source + Network intelligence ---
        self._run_endpoint_and_network_analysis()

        # Restore detailed log info as before
        if hasattr(self, 'log_view'):
            bin_info = results.get('binary_info', {})
            self.log_view.append('[INFO] Analysis complete.')
            if bin_info:
                self.log_view.append(f"[INFO] Architecture: {bin_info.get('arch', 'Unknown')}")
                self.log_view.append(f"[INFO] Entry point: {bin_info.get('entry_point', 'Unknown')}")
                self.log_view.append(f"[INFO] Sections: {[s['name'] for s in results.get('sections', [])]}")
            self.log_view.append(f"[INFO] Disassembly view updated with {len(instructions)} instructions.")
            # Append C decompilation output (always) using Ghidra, not AI
            try:
                ghidra_result = self.decompiler_manager._run_ghidra(self.current_file_path)
                # Extract only actual C code blocks from Ghidra output
                c_blocks = []
                if ghidra_result:
                    lines = ghidra_result.splitlines()
                    current_block = []
                    inside_c = False
                    for line in lines:
                        # Skip banners, decompiling lines, and separators
                        if line.strip().startswith("Decompiling:") or line.strip().startswith("[ERROR]"):
                            continue
                        if line.strip() == "=" * 60 or line.strip() == "=" or line.strip() == "":
                            if current_block:
                                c_blocks.append("\n".join(current_block).strip())
                                current_block = []
                            inside_c = False
                            continue
                        # Most C code lines contain ';', '{', '}', or comments
                        if any(x in line for x in [';', '{', '}', '//', '#include', 'return', 'int ', 'void ', 'char ', 'float ', 'double ', 'if(', 'for(', 'while(']):
                            inside_c = True
                        if inside_c:
                            current_block.append(line)
                    # Append last block
                    if current_block:
                        c_blocks.append("\n".join(current_block).strip())
                c_code = "\n\n".join([b for b in c_blocks if len(b) > 20])  # Only keep non-trivial blocks
                self.log_view.append('[C DECOMPILATION OUTPUT]')
                if c_code:
                    self.log_view.append(c_code)
                else:
                    # If Ghidra returned an error, show it
                    if ghidra_result and ('error' in ghidra_result.lower() or 'failed' in ghidra_result.lower()):
                        self.log_view.append(ghidra_result.strip())
                    else:
                        self.log_view.append('[ERROR] Ghidra decompilation failed or returned no usable C code.')
            except Exception as e:
                self.log_view.append(f'[ERROR] Ghidra decompilation failed: {e}')
        # --- Compose analysis log for AI decompilation ---
        analysis_log = self.compose_analysis_log(results)
        results['analysis_log'] = analysis_log  # Store for later use
        self.last_analysis_results = results
        # Build the structured program model (single source of truth for CFG,
        # re-analysis, pseudocode) instead of re-parsing the disassembly text.
        try:
            self.program_model = ProgramModel.from_results(results)
            if hasattr(self, 'log_view') and self.program_model.instructions:
                s = self.program_model.stats()
                self.log_view.append(
                    f"[MODEL] {s['instructions']} instructions, "
                    f"{s['basic_blocks']} basic blocks, {s['edges']} CFG edges."
                )
        except Exception as e:
            self.program_model = None
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Could not build program model: {e}")

        # Populate the Insights panel + status bar from the gathered facts.
        self._update_insights(results)

        # Give the Security Audit panel everything it needs for the concrete map.
        if hasattr(self, 'security_audit_panel'):
            self.security_audit_panel.set_context(
                path=self.current_file_path,
                sections=results.get('sections', []),
                functions=results.get('functions', []),
                instructions=(self.program_model.instructions
                              if getattr(self, 'program_model', None) else []),
                imports=results.get('imports', []),
                source_dir=getattr(self, '_electron_src_dir', None))

        # Point the Privesc-surface panel at the loaded binary.
        if hasattr(self, 'privesc_panel'):
            self.privesc_panel.set_target(self.current_file_path)

        # Feed the Visualization tab (entropy map + basic-block CFG) from real data.
        try:
            if hasattr(self, 'viz_widget'):
                if self.current_file_path and os.path.isfile(self.current_file_path):
                    with open(self.current_file_path, 'rb') as fh:
                        self.viz_widget.set_binary_data(fh.read())
                if getattr(self, 'program_model', None) and self.program_model.instructions:
                    blocks = [{
                        'address': b.start,
                        'size': len(b.instructions),
                        'instructions': b.instructions,
                        'targets': b.successors,
                    } for b in self.program_model.basic_blocks()]
                    self.viz_widget.update_cfg(blocks)
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Visualization update failed: {e}")

        # NOTE: C decompilation is handled asynchronously by DecompileWorker below.
        # The previous synchronous decompile_parallel() call here blocked the UI
        # thread for up to 5 minutes and returned nothing usable ('consensus' is
        # not a key of decompile_parallel's result), so it was removed.
        # If AI decompilation is checked, start the async worker for the Source Code tab
        if self.ai_decompile_cb.isChecked():
            self.decompile_worker = DecompileWorker(
                self.decompiler_manager,
                analysis_log,
                self.current_file_path
            )
            self.decompile_worker.decompile_complete.connect(self.on_decompile_complete)
            self.decompile_worker.progress_update.connect(self.update_progress)
            self.decompile_worker.start()
        self.progress_bar.setVisible(False)