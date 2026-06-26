# -*- coding: utf-8 -*-
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QStatusBar, QFileDialog, QPushButton,
    QProgressBar, QLabel, QComboBox, QCheckBox, QLineEdit, QInputDialog,
    QApplication
) # All widgets imported at top

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QAction
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
            print("[DEBUG] Starting binary analysis...")
            self.progress_update.emit("Loading binary...")

            if not self.binary_loader.load(self.file_path):
                print("[DEBUG] Binary loading failed")
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
                            'virtual_address': getattr(s, 'virtual_address', 0)
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
                        if hasattr(header, 'machine_type'):
                            machine = str(header.machine_type)
                            if 'AMD64' in machine or 'X86_64' in machine:
                                arch = Architecture.X86_64
                            elif 'I386' in machine or 'X86' in machine:
                                arch = Architecture.X86
                            elif 'ARM64' in machine:
                                arch = Architecture.ARM64
                            elif 'ARM' in machine:
                                arch = Architecture.ARM
                        elif hasattr(header, 'arch'):
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
                        print(f"[DEBUG] Disassembler initialized for arch: {arch}")
                    else:
                        print("[DEBUG] Could not detect architecture, skipping disassembly.")
                except Exception as e:
                    print(f"[DEBUG] Architecture detection/init error: {e}")
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
                                print(f"[DEBUG] Example instructions: {[i['mnemonic'] for i in instructions[:10]]}")
                                print(f"[DEBUG] Generated {len(instructions)} instructions")
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
                print(f"[DEBUG] Function discovery failed: {fe}")

            self.analysis_complete.emit({
                'binary_info': bin_info,
                'instructions': instructions,
                'sections': sections,
                'functions': functions,
                'file_path': self.file_path
            })

        except Exception as e:
            print(f"[DEBUG] Critical error during binary analysis: {str(e)}")
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
            print(f"[DecompileWorker] Something went wrong during decompilation: {str(e)}")
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
            print(f"[ThreatAnalysisWorker] Threat analysis failed: {str(e)}")
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
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setFormat("Analyzing binary...")
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[INFO] Starting analysis for: {file_path}")
        self.analysis_worker = BinaryAnalysisWorker(self.binary_loader, self.disassembler, file_path)
        self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_worker.progress_update.connect(self.update_progress)
        self.analysis_worker.start()

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
        """Open a binary file and start analysis."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "All Files (*)")
        if file_path:
            self.current_file_path = file_path
            if hasattr(self, 'file_label'):
                self.file_label.setText(file_path)
            self.log_view.append(f"[INFO] Opened file: {file_path}")
            # Start binary analysis
            self.start_binary_analysis(file_path)

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
        from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
        from PyQt6.QtCore import Qt
        self.welcome_widget = QWidget()
        layout = QVBoxLayout()
        label = QLabel("<h2>Welcome to the Reverse Engineering Platform</h2>\n<p style='font-size:16px;'>Choose your mode:</p>")
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(label)
        btn_cracking = QPushButton("Cracking")
        btn_security = QPushButton("Security")
        btn_cracking.setMinimumHeight(40)
        btn_security.setMinimumHeight(40)
        btn_cracking.setStyleSheet("font-size:16px;")
        btn_security.setStyleSheet("font-size:16px;")
        layout.addWidget(btn_cracking)
        layout.addWidget(btn_security)
        self.welcome_widget.setLayout(layout)
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
        # Restore the original main window stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #232629;
                color: #f5f6fa;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 14px;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 8px;
                background: #282c34;
                padding: 6px;
            }
            QTabBar::tab {
                background: #282c34;
                color: #f5f6fa;
                border-radius: 8px 8px 0 0;
                padding: 10px 20px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #353b45;
                color: #61dafb;
            }
            QTabBar::tab:hover {
                background: #3c4048;
            }
            QPushButton {
                background-color: #353b45;
                color: #f5f6fa;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 8px 18px;
                margin: 4px;
            }
            QPushButton:hover {
                background-color: #61dafb;
                color: #232629;
            }
            QLineEdit, QTextEdit {
                background: #232629;
                color: #f5f6fa;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 6px;
            }
            QLabel {
                color: #f5f6fa;
            }
            QScrollBar:vertical {
                background: #232629;
                width: 12px;
                margin: 22px 0 22px 0;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #353b45;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
        """)
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
        self.setWindowTitle("Ultimate Reverse Engineering Platform")
        # Only set geometry if it fits the screen
        screen = self.screen() or self.window().screen() if hasattr(self, 'window') else None
        if screen:
            screen_size = screen.availableGeometry()
            width = min(1200, screen_size.width())
            height = min(800, screen_size.height())
            x = screen_size.x() + 100
            y = screen_size.y() + 100
            self.setGeometry(x, y, width, height)
        else:
            self.setGeometry(100, 100, 1200, 800)


        # Central widget with splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Main horizontal splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel (Binary Info + Controls)
        left_panel = self.create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Center panel (Analysis Views)
        center_panel = self.create_center_panel()
        main_splitter.addWidget(center_panel)
        
        # Right panel (Advanced Features)
        right_panel = self.create_right_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([300, 800, 500])
        main_layout.addWidget(main_splitter)

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
        
        # Analysis tabs
        self.analysis_tabs = QTabWidget()

        # Disassembly view
        disassembly_tab_widget = QWidget()
        disassembly_layout = QVBoxLayout(disassembly_tab_widget)
        self.disassembly_view = QTextEdit()
        self.disassembly_view.setReadOnly(True)
        self.disassembly_view.setFont(QFont("Consolas", 9))
        disassembly_layout.addWidget(self.disassembly_view)
        # Add Download Disassembly button
        self.download_disassembly_btn = QPushButton("Download Disassembly")
        disassembly_layout.addWidget(self.download_disassembly_btn)
        self.download_disassembly_btn.clicked.connect(self.download_disassembly)
        self.analysis_tabs.addTab(disassembly_tab_widget, "Disassembly")

        # Endpoint Detection tab (new)
        self.endpoint_detection_view = QTextEdit()
        self.endpoint_detection_view.setReadOnly(True)
        self.endpoint_detection_view.setFont(QFont("Consolas", 9))
        self.analysis_tabs.addTab(self.endpoint_detection_view, "Endpoint Detection")

        # Source Code tab (for AI/traditional decompilation results)
        self.source_code_view = QTextEdit()
        self.source_code_view.setReadOnly(True)
        self.source_code_view.setFont(QFont("Consolas", 9))
        self.analysis_tabs.addTab(self.source_code_view, "Source Code")

        # --- Pseudocode tab with toggle ---
        from src.gui.pseudocode_toggle_widget import PseudocodeToggleWidget
        self.pseudocode_tab_widget = QWidget()
        pseudo_layout = QVBoxLayout(self.pseudocode_tab_widget)
        self.pseudocode_toggle = PseudocodeToggleWidget()
        pseudo_layout.addWidget(self.pseudocode_toggle)
        self.pseudocode_view = QTextEdit()
        self.pseudocode_view.setReadOnly(True)
        self.pseudocode_view.setFont(QFont("Consolas", 9))
        pseudo_layout.addWidget(self.pseudocode_view)
        self.analysis_tabs.addTab(self.pseudocode_tab_widget, "Pseudocode")
        self.pseudocode_toggle.toggle_changed.connect(self.update_pseudocode_tab)
        # --- End Pseudocode tab with toggle ---

        # AI Analysis Panel
        self.ai_analysis_panel = AIAnalysisPanel()
        self.analysis_tabs.addTab(self.ai_analysis_panel, "AI Decompilation")
        # Connect AIAnalysisPanel buttons to MainWindow handlers
        self.ai_analysis_panel.reanalyze_btn.clicked.connect(self.reanalyze_with_ai)
        self.ai_analysis_panel.enhance_btn.clicked.connect(self.enhance_with_ai_comments)
        self.ai_analysis_panel.export_btn.clicked.connect(self.export_ai_results)
        self.ai_analysis_panel.summarize_btn.clicked.connect(self.summarize_function_with_ai)
        self.ai_analysis_panel.qa_btn.clicked.connect(self.ask_ai_about_code)
        
        # Advanced Visualization
        self.viz_widget = AdvancedVisualizationWidget()
        self.analysis_tabs.addTab(self.viz_widget, "Visualization")

        # CFG Viewer integration
        self.cfg_btn = QPushButton("Show Control Flow Graph (CFG)")
        self.cfg_btn.clicked.connect(self.show_cfg_viewer)
        self.analysis_tabs.addTab(self.cfg_btn, "CFG Viewer")

        # Full Software Analysis tab
        try:
            from src.gui.full_software_panel import FullSoftwarePanel
            self.full_software_panel = FullSoftwarePanel()
            self.analysis_tabs.addTab(self.full_software_panel, "Full Software")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Full Software panel: {e}")

        # Crypto Tools integration
        try:
            from src.gui.crypto_tools_panel import CryptoToolsPanel
            self.crypto_tools_panel = CryptoToolsPanel()
            self.analysis_tabs.addTab(self.crypto_tools_panel, "Crypto Tools")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Crypto Tools panel: {e}")

        # Key Analysis integration
        try:
            from src.gui.key_analysis_panel import KeyAnalysisPanel
            self.key_analysis_panel = KeyAnalysisPanel()
            self.analysis_tabs.addTab(self.key_analysis_panel, "Key Analysis")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Key Analysis panel: {e}")

        # Security Audit integration
        try:
            from src.gui.security_audit_panel import SecurityAuditPanel
            self.security_audit_panel = SecurityAuditPanel()
            self.analysis_tabs.addTab(self.security_audit_panel, "Security Audit")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Security Audit panel: {e}")
        
        # Network Capture integration
        try:
            from src.gui.network_capture_panel import NetworkCapturePanel
            self.network_capture_panel = NetworkCapturePanel()
            self.analysis_tabs.addTab(self.network_capture_panel, "Network Capture")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to load Network Capture panel: {e}")
        
        # Log view
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 8))
        # Add download button below log view
        log_tab_widget = QWidget()
        log_tab_layout = QVBoxLayout(log_tab_widget)
        log_tab_layout.addWidget(self.log_view)
        self.download_log_btn = QPushButton("Download Log File")
        log_tab_layout.addWidget(self.download_log_btn)
        self.download_log_btn.clicked.connect(self.download_log_file)
        self.analysis_tabs.addTab(log_tab_widget, "Analysis Log")
        
        # Project Analysis tab (new)
        self.project_analysis_tab = ProjectAnalysisTab()
        self.analysis_tabs.addTab(self.project_analysis_tab, "Project Analysis")
        
        layout.addWidget(self.analysis_tabs)
        return center_widget

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
        # Add permanent widgets to status bar
        self.analysis_status = QLabel("Ready")
        self.status_bar.addPermanentWidget(self.analysis_status)

    def create_right_panel(self):
        right_widget = QWidget()
        layout = QVBoxLayout(right_widget)
        
        # Right panel tabs
        right_tabs = QTabWidget()
        
        # Threat Intelligence view
        threat_widget = QWidget()
        threat_layout = QVBoxLayout(threat_widget)
        
        threat_layout.addWidget(QLabel("Threat Intelligence Results:"))
        self.threat_results_view = QTextEdit()
        self.threat_results_view.setReadOnly(True)
        threat_layout.addWidget(self.threat_results_view)
        
        threat_layout.addWidget(QLabel("Extracted IOCs:"))
        self.ioc_list = QTreeWidget()
        self.ioc_list.setHeaderLabels(["Type", "Value", "Context"])
        threat_layout.addWidget(self.ioc_list)
        
        right_tabs.addTab(threat_widget, "Threat Intel")
        
        # Collaboration view (placeholder)
        collab_widget = QWidget()
        collab_layout = QVBoxLayout(collab_widget)
        collab_layout.addWidget(QLabel("Collaboration features coming soon..."))
        right_tabs.addTab(collab_widget, "Collaboration")
        
        # Settings view
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        
        settings_layout.addWidget(QLabel("AI Model:"))
        self.model_combo = QComboBox()
        self.model_combo.addItems(["Ollama (Local)"])
        self.model_combo.setCurrentIndex(0)
        self.model_combo.currentIndexChanged.connect(self.on_model_changed)
        settings_layout.addWidget(self.model_combo)
        settings_layout.addWidget(QLabel("OpenAI API Key:"))
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("Enter your OpenAI API key here")
        settings_layout.addWidget(self.api_key_edit)
        
        settings_layout.addWidget(QLabel("Visualization Options:"))
        self.entropy_cb = QCheckBox("Show Entropy Analysis")
        self.entropy_cb.setChecked(True)
        settings_layout.addWidget(self.entropy_cb)
        
        settings_layout.addStretch()
        right_tabs.addTab(settings_widget, "Settings")
        
        layout.addWidget(right_tabs)
        return right_widget

    def create_left_panel(self):
        left_widget = QWidget()
        layout = QVBoxLayout(left_widget)
        
        # File info and controls
        file_info_group = QWidget()
        file_layout = QVBoxLayout(file_info_group)
        
        # Open file button
        self.open_btn = QPushButton("Open Binary File")
        self.open_btn.clicked.connect(self.open_file)
        file_layout.addWidget(self.open_btn)
        
        # File path label
        self.file_label = QLabel("No file loaded")
        file_layout.addWidget(self.file_label)
        
        # Analysis options
        options_group = QWidget()
        options_layout = QVBoxLayout(options_group)
        
        self.ai_decompile_cb = QCheckBox("Enable AI Decompilation")
        self.ai_decompile_cb.setChecked(True)
        options_layout.addWidget(self.ai_decompile_cb)
        
        self.threat_intel_cb = QCheckBox("Enable Threat Intelligence")
        self.threat_intel_cb.setChecked(True)
        options_layout.addWidget(self.threat_intel_cb)
        
        self.collaboration_cb = QCheckBox("Enable Collaboration")
        options_layout.addWidget(self.collaboration_cb)
        
        file_layout.addWidget(options_group)
        layout.addWidget(file_info_group)
        
        # Binary sections tree
        self.binary_info_tree = QTreeWidget()
        self.binary_info_tree.setHeaderLabels(["Section", "Address", "Size"])
        layout.addWidget(QLabel("Binary Sections:"))
        layout.addWidget(self.binary_info_tree)

        # Functions list (double-click to jump to the address in Disassembly).
        self.functions_tree = QTreeWidget()
        self.functions_tree.setHeaderLabels(["Function", "Address"])
        self.functions_tree.itemDoubleClicked.connect(self.on_function_selected)
        layout.addWidget(QLabel("Functions (double-click to navigate):"))
        layout.addWidget(self.functions_tree)

        # Progress bar
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
                self.analysis_tabs.setCurrentWidget(self.disassembly_view)
            else:
                if hasattr(self, 'log_view'):
                    self.log_view.append(f"[INFO] Address {addr_text} not in the disassembled range.")
        except Exception as e:
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[WARN] Could not navigate to function: {e}")

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
        # Update AI analysis panel with results as before
        self.ai_analysis_panel.update_analysis_results(results)
        # Try to show Ghidra/RetDec, but if they fail, show AI (Ollama) output if available
        ghidra_result = results.get('ghidra', {})
        retdec_result = results.get('retdec', {})
        ai_result = results.get(getattr(self.decompiler_manager, 'DecompilerEngine', None).LLM4DECOMPILE if hasattr(self.decompiler_manager, 'DecompilerEngine') else 'llm4decompile', {})
        # Fallback: try string key if enum is not available
        if not ai_result:
            ai_result = results.get('llm4decompile', {})
            if not ai_result:
                # Try enum type if present
                from src.core.decompiler_manager import DecompilerEngine
                ai_result = results.get(DecompilerEngine.LLM4DECOMPILE, {})
        code = None
        engine_used = None
        # Prefer Ghidra, then RetDec, then AI (Ollama)
        if ghidra_result.get('success') and ghidra_result.get('code') and 'error' not in ghidra_result.get('code', '').lower() and 'failed' not in ghidra_result.get('code', '').lower():
            code = ghidra_result['code']
            engine_used = 'Ghidra'
        elif retdec_result.get('success') and retdec_result.get('code') and 'error' not in retdec_result.get('code', '').lower() and 'failed' not in retdec_result.get('code', '').lower():
            code = retdec_result['code']
            engine_used = 'RetDec'
        elif ai_result.get('success') and ai_result.get('code'):
            code = ai_result['code']
            engine_used = 'Ollama AI'
        else:
            code = "[ERROR] All decompilation engines failed. No C code available."
            engine_used = 'None'
        # Chunked, non-blocking loading for very large code output
        from PyQt6.QtCore import QTimer
        self.source_code_view.clear()
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setMaximum(0)  # Indeterminate
        code_lines = code.splitlines(keepends=True)
        chunk_size = 5000
        total_lines = len(code_lines)
        self._source_code_chunk_index = 0
        def append_next_chunk():
            start = self._source_code_chunk_index
            end = min(start + chunk_size, total_lines)
            chunk = ''.join(code_lines[start:end])
            from PyQt6.QtGui import QTextCursor
            self.source_code_view.moveCursor(QTextCursor.MoveOperation.End)
            self.source_code_view.insertPlainText(chunk)
            self._source_code_chunk_index = end
            if hasattr(self, 'progress_bar'):
                self.progress_bar.setFormat(f"Loading C code: {end}/{total_lines} lines")
            if end < total_lines:
                QTimer.singleShot(10, append_next_chunk)
            else:
                if hasattr(self, 'progress_bar'):
                    self.progress_bar.setVisible(False)

        append_next_chunk()

        # Check if output is not valid C code and warn the user (for AI output or others)
        c_code = self.source_code_view.toPlainText()
        c_keywords = ['#include', 'int main', 'void ', 'char ', 'struct ', 'return ', 'printf', 'scanf']
        is_valid_c = any(keyword in c_code for keyword in c_keywords)
        is_generic = False
        # Heuristic: if code is just wrappers or has too many asm/volatile/extern lines, or function names are just instruction mnemonics
        suspicious_patterns = [
            'extern "C" void', '__asm__', 'volatile', 'mov_', 'call_', 'jmp_', 'test_', 'push_', 'pop_', 'ret()', 'add_', 'sub_', 'xor_', 'and_', 'or_', 'shr_', 'shl_', 'ror_', 'rol_'
        ]
        generic_count = sum(pattern in c_code for pattern in suspicious_patterns)
        if not is_valid_c or generic_count >= 3:
            is_generic = True
            if hasattr(self, 'log_view'):
                self.log_view.append("[WARNING] The output does not appear to be valid C code. It may be an explanation, generic wrappers, or hallucinated code instead of real decompiled source.")
                self.log_view.append("[ADVICE] If this is an AI result, try using a simpler or unpacked binary. If the binary is packed (e.g., UPX), unpack it and retry. If using a custom model, ensure it is trained for binary-to-C translation.")
            self.source_code_view.append("\n// [WARNING] The output does not appear to be valid C code. It may be an explanation, generic wrappers, or hallucinated code instead of real decompiled source.\n")
            self.source_code_view.append("// [ADVICE] Try using a simpler or unpacked binary. If the binary is packed (e.g., UPX), unpack it and retry.\n")

        # --- Analysis log error/missing check for AI decompilation ---
        if hasattr(self, 'last_analysis_results'):
            analysis_log = self.last_analysis_results.get('analysis_log', '')
            binary_path = getattr(self, 'current_file_path', None)
            upx_detected = False
            # If the analysis log is mostly errors or missing sections, block AI decompilation and show a warning
            error_lines = [l for l in analysis_log.splitlines() if any(
                err in l.lower() for err in [
                    'unable to find the section',
                    'can\'t read',
                    'failed',
                    'error',
                    'incomplete',
                    'not found',
                    'missing',
                    'parse',
                    'exception',
                    'no program loaded',
                    'not supported',
                    'unsupported',
                    'not implemented'
                ])]
            non_empty_lines = [l for l in analysis_log.splitlines() if l.strip()]
            if len(non_empty_lines) > 0 and len(error_lines) / len(non_empty_lines) > 0.6:
                # More than 60% of the log is errors: block AI decompilation
                if hasattr(self, 'log_view'):
                    self.log_view.append("[FATAL] The analysis log is mostly errors or missing sections. AI decompilation is blocked because results will be meaningless.\nPlease unpack, fix the binary, or use a different file.")
                self.source_code_view.setPlainText("// [FATAL] The analysis log is mostly errors or missing sections. AI decompilation is blocked because results will be meaningless.\n// Please unpack, fix the binary, or use a different file.\n")
                # Optionally, early return here to block further display
                return
            # --- UPX/packer detection as before ---
            if any(packer in analysis_log.lower() for packer in ['upx', 'packed', 'packer', 'aspack', 'petite', 'fsg']):
                upx_detected = True
            else:
                try:
                    from src.core.ai_decompiler import AIDecompiler
                    if binary_path and AIDecompiler.is_upx_packed(binary_path):
                        upx_detected = True
                except Exception:
                    pass
            if upx_detected:
                if hasattr(self, 'log_view'):
                    self.log_view.append("[WARNING] This binary appears to be packed (e.g., with UPX or another packer). Please unpack it before attempting AI decompilation for best results.")
                    try:
                        from src.core.ai_decompiler import AIDecompiler
                        unpacked_path = AIDecompiler.auto_unpack_upx(binary_path) if binary_path else None
                        if unpacked_path:
                            self.log_view.append(f"[INFO] The binary was auto-unpacked to {unpacked_path}. Please re-run analysis on this file for improved AI results.")
                        else:
                            self.log_view.append("[INFO] UPX was not found or auto-unpack failed. Please unpack manually with 'upx -d <file>' and retry.")
                    except Exception:
                        self.log_view.append("[INFO] UPX auto-unpack check failed. Please unpack manually if needed.")
                self.source_code_view.append("// [WARNING] This binary appears to be packed (e.g., with UPX or another packer). Please unpack it before attempting AI decompilation for best results.\n")
        # --- Add analysis log viewer button/panel ---
        if not hasattr(self, 'analysis_log_viewer_btn'):
            from PyQt6.QtWidgets import QPushButton, QDialog, QVBoxLayout, QTextEdit
            def show_analysis_log():
                dlg = QDialog(self)
                dlg.setWindowTitle("Analysis Log Viewer")
                layout = QVBoxLayout()
                txt = QTextEdit()
                txt.setReadOnly(True)
                txt.setPlainText(self.last_analysis_results.get('analysis_log', 'No analysis log available.'))
                layout.addWidget(txt)
                dlg.setLayout(layout)
                dlg.resize(900, 600)
                dlg.exec()
            self.analysis_log_viewer_btn = QPushButton("View Analysis Log", self)
            self.analysis_log_viewer_btn.clicked.connect(show_analysis_log)
            if hasattr(self, 'log_view'):
                self.log_view.append("[INFO] You can view the raw analysis log by clicking the 'View Analysis Log' button below the log panel.")
            # Add the button to the main window layout (if not already present)
            if hasattr(self, 'log_view') and hasattr(self.log_view, 'parentWidget'):
                parent = self.log_view.parentWidget()
                if hasattr(parent, 'layout') and parent.layout():
                    parent.layout().addWidget(self.analysis_log_viewer_btn)


        if engine_used and engine_used != 'None':
            self.log_view.append(f"[INFO] Source Code tab updated with {engine_used} C decompilation.")
            self.log_view.append(f"[INFO] Decompilation complete ({engine_used})")
        else:
            self.log_view.append("[ERROR] All decompilation engines failed. No C code available.")
            self.log_view.append("[INFO] Decompilation complete")

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

        # --- Endpoint Detection: always generate and display report in Endpoint Detection tab ---
        endpoint_results = format_endpoint_results(detect_endpoints(disasm_lines))
        self.endpoint_detection_view.setPlainText(endpoint_results)

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
