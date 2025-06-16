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

from src.core.universal_loader import UniversalLoader
from src.core.disassembler import DisassemblerEngine, Architecture
from src.core.unpacker import BasicUnpacker
from src.core.decompiler_manager import DecompilerManager, DecompilerEngine
from src.core.ai_decompiler import AIDecompiler
from src.intelligence.threat_intel import ThreatIntelligence, IOCExtractor
from src.gui.advanced_viewer import AdvancedVisualizationWidget, AIAnalysisPanel
from src.gui.network_capture_panel import NetworkCapturePanel
from src.gui.full_software_panel import FullSoftwarePanel

class BinaryAnalysisWorker(QThread):
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

            # UniversalLoader: check file_type
            file_type = getattr(self.binary_loader, 'file_type', None)
            bin_info = {'type': str(file_type), 'path': self.file_path}
            instructions = []
            sections = []

            # Try to extract sections if possible
            if hasattr(self.binary_loader, 'parsed') and self.binary_loader.parsed is not None:
                # If parsed is a dict or has sections, try to extract
                parsed = self.binary_loader.parsed
                if hasattr(parsed, 'sections'):
                    sections = [{
                        'name': getattr(s, 'name', ''),
                        'size': getattr(s, 'size', 0),
                        'virtual_address': getattr(s, 'virtual_address', 0)
                    } for s in getattr(parsed, 'sections', [])]
                    bin_info['sections'] = sections
                elif isinstance(parsed, dict) and 'sections' in parsed:
                    sections = parsed['sections']
                    bin_info['sections'] = sections
                else:
                    bin_info['sections'] = []
            else:
                bin_info['sections'] = []

            # Only try disassembly for PE/ELF/MACHO
            if file_type and str(file_type) in ['FileType.PE', 'FileType.ELF', 'FileType.MACHO'] and sections:
                # --- Initialize disassembler with correct architecture ---
                arch = None
                try:
                    # Try to detect architecture from LIEF parsed binary
                    parsed = getattr(self.binary_loader, 'parsed', None)
                    if parsed is not None and hasattr(parsed, 'header'):
                        if hasattr(parsed.header, 'machine_type'):
                            machine = str(parsed.header.machine_type)
                            if 'AMD64' in machine or 'X86_64' in machine:
                                arch = Architecture.X86_64
                            elif 'I386' in machine or 'X86' in machine:
                                arch = Architecture.X86
                            elif 'ARM64' in machine:
                                arch = Architecture.ARM64
                            elif 'ARM' in machine:
                                arch = Architecture.ARM
                        elif hasattr(parsed.header, 'arch'):
                            arch_val = str(parsed.header.arch)
                            if 'x86_64' in arch_val:
                                arch = Architecture.X86_64
                            elif 'x86' in arch_val:
                                arch = Architecture.X86
                            elif 'arm64' in arch_val:
                                arch = Architecture.ARM64
                            elif 'arm' in arch_val:
                                arch = Architecture.ARM
                    if arch is None:
                        # Fallback: guess from file type
                        if str(file_type) == 'FileType.PE':
                            arch = Architecture.X86_64
                        elif str(file_type) == 'FileType.ELF':
                            arch = Architecture.X86_64
                        elif str(file_type) == 'FileType.MACHO':
                            arch = Architecture.X86_64
                    if arch is not None:
                        self.disassembler.initialize(arch)
                        print(f"[DEBUG] Disassembler initialized for arch: {arch}")
                    else:
                        print("[DEBUG] Could not detect architecture, skipping disassembly.")
                except Exception as e:
                    print(f"[DEBUG] Architecture detection/init error: {e}")
                # --- End disassembler initialization ---
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
                            print(f"[DEBUG] Generated {len(instructions)} instructions")
            else:
                # For RAW/unknown files, skip disassembly
                pass

            self.analysis_complete.emit({
                'binary_info': bin_info,
                'instructions': instructions,
                'sections': sections,
                'file_path': self.file_path
            })

        except Exception as e:
            print(f"[DEBUG] Critical error: {str(e)}")
            self.progress_update.emit(f"Error: {str(e)}")

class DecompileWorker(QThread):
    decompile_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)

    def __init__(self, decompiler_manager, assembly_code, file_path):
        super().__init__()
        self.decompiler_manager = decompiler_manager
        self.assembly_code = assembly_code
        self.file_path = file_path

    def run(self):
        try:
            self.progress_update.emit("Starting AI decompilation...")
            
            # Run parallel decompilation with multiple engines
            results = self.decompiler_manager.decompile_parallel(
                self.assembly_code, 
                self.file_path
            )
            
            # Get consensus result
            consensus = self.decompiler_manager.get_consensus_result(results)
            results['consensus'] = consensus
            
            self.decompile_complete.emit(results)
            
        except Exception as e:
            print(f"[DEBUG] Decompilation error: {str(e)}")
            self.progress_update.emit(f"Decompilation error: {str(e)}")

class ThreatAnalysisWorker(QThread):
    threat_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)

    def __init__(self, file_path, threat_intel):
        super().__init__()
        self.file_path = file_path
        self.threat_intel = threat_intel

    def run(self):
        try:
            self.progress_update.emit("Analyzing threat intelligence...")
            
            # Calculate file hash
            with open(self.file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Analyze against threat intelligence
            threat_results = self.threat_intel.analyze_binary_hash(file_hash)
            
            self.threat_complete.emit({
                'hash': file_hash,
                'results': threat_results
            })
            
        except Exception as e:
            print(f"[DEBUG] Threat analysis error: {str(e)}")
            self.progress_update.emit(f"Threat analysis error: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self, settings, plugin_manager):
        # ... (existing code)
        pass  # placeholder for context
        super().__init__()
        self.settings = settings
        self.plugin_manager = plugin_manager
        self.binary_loader = UniversalLoader()
        self.disassembler = DisassemblerEngine()
        self.current_file_path = None
        
        # Initialize AI components
        self.ai_decompiler = AIDecompiler(model_type="ollama")
        self.decompiler_manager = DecompilerManager()
        self.decompiler_manager.register_engine(
            DecompilerEngine.LLM4DECOMPILE, 
            self.ai_decompiler
        )
        # Map model combo index to AIDecompiler model_type
        self.model_type_map = {
            0: "ollama",
            1: "huggingface",
            2: "openai"
        }
        
        # Initialize threat intelligence
        self.threat_intel = ThreatIntelligence()
        self.ioc_extractor = IOCExtractor()
        
        self.setWindowTitle("Reverse Engineering Platform")
        # Set a safe default window size and min/max
        self.setMinimumSize(1000, 600)
        self.resize(1200, 800)
        screen = self.screen() or self.window().screen() if hasattr(self, 'window') else None
        if screen:
            screen_size = screen.availableGeometry().size()
            max_width = min(1920, screen_size.width())
            max_height = min(1080, screen_size.height())
            self.setMaximumSize(max_width, max_height)
        self.init_ui()
        self.setup_menu()
        self.setup_status_bar()

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

    def init_ui(self):
        self.setWindowTitle("Ultimate Reverse Engineering Platform")
        self.setGeometry(100, 100, 1600, 1000)

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

    def create_center_panel(self):
        center_widget = QWidget()
        layout = QVBoxLayout(center_widget)
        
        # Analysis tabs
        self.analysis_tabs = QTabWidget()

        # Disassembly view
        self.disassembly_view = QTextEdit()
        self.disassembly_view.setReadOnly(True)
        self.disassembly_view.setFont(QFont("Consolas", 9))
        self.analysis_tabs.addTab(self.disassembly_view, "Disassembly")

        # Source Code tab (for AI/traditional decompilation results)
        self.source_code_view = QTextEdit()
        self.source_code_view.setReadOnly(True)
        self.source_code_view.setFont(QFont("Consolas", 9))
        self.analysis_tabs.addTab(self.source_code_view, "Source Code")

        # Pseudocode tab
        self.pseudocode_view = QTextEdit()
        self.pseudocode_view.setReadOnly(True)
        self.pseudocode_view.setFont(QFont("Consolas", 9))
        self.analysis_tabs.addTab(self.pseudocode_view, "Pseudocode")

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
        self.analysis_tabs.addTab(self.log_view, "Analysis Log")
        
        layout.addWidget(self.analysis_tabs)
        return center_widget

    def on_model_changed(self, index):
        """Handle AI model selection change from the combo box."""
        model_type_map = {
            0: "ollama",
            1: "huggingface",
            2: "openai"
        }
        model_type = model_type_map.get(index, "ollama")
        # Only update if changed
        if getattr(self, 'ai_decompiler', None) is not None and getattr(self.ai_decompiler, 'model_type', None) != model_type:
            # Recreate and re-register the AI decompiler with the new model type
            self.ai_decompiler = AIDecompiler(model_type=model_type)
            self.decompiler_manager.register_engine(
                DecompilerEngine.LLM4DECOMPILE,
                self.ai_decompiler
            )
            if hasattr(self, 'log_view'):
                self.log_view.append(f"[INFO] Switched AI model to: {self.model_combo.currentText()}")

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
        self.model_combo.addItems(["Ollama (Local)", "HuggingFace", "OpenAI GPT-4"])
        self.model_combo.setCurrentIndex(0)
        self.model_combo.currentIndexChanged.connect(self.on_model_changed)
        settings_layout.addWidget(self.model_combo)
        settings_layout.addWidget(QLabel("OpenAI API Key:"))
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("Enter your OpenAI API key here")
        settings_layout.addWidget(self.api_key_edit)
        self.save_api_btn = QPushButton("Save API Key")
        settings_layout.addWidget(self.save_api_btn)
        self.save_api_btn.clicked.connect(self.save_openai_api_key)
        
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
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        return left_widget

    def show_cfg_viewer(self):
        """Show the control flow graph for the current disassembly."""
        try:
            from src.gui.cfg_viewer import CFGViewer
            # Parse instructions from disassembly view
            disasm_text = self.disassembly_view.toPlainText()
            lines = disasm_text.strip().splitlines()
            instructions = []
            for idx, line in enumerate(lines):
                # Naive parsing: assume format 'mnemonic operands'
                parts = line.strip().split(None, 1)
                mnemonic = parts[0] if parts else ''
                op_str = parts[1] if len(parts) > 1 else ''
                instructions.append({'address': idx, 'mnemonic': mnemonic, 'op_str': op_str})
            if not instructions:
                self.log_view.append("[WARN] No instructions to visualize for CFG.")
                return
            self.cfg_viewer = CFGViewer(instructions)
            self.cfg_viewer.setWindowTitle("Control Flow Graph (CFG)")
            self.cfg_viewer.show()
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to show CFG: {e}")

    def update_pseudocode_tab(self):
        """Refresh the pseudocode tab using MultiArchDisassembler."""
        try:
            from src.core.multiarch_disassembler import MultiArchDisassembler
            mad = MultiArchDisassembler(self.current_file_path)
            mad.load()
            pseudo = mad.to_pseudocode()
            self.pseudocode_view.setPlainText(pseudo)
        except Exception as e:
            self.pseudocode_view.setPlainText(f"[ERROR] Could not generate pseudocode: {e}")

    def run_full_decompilation(self):
        """Run AI decompilation on all code sections (not just .text) and show the best result."""
        from src.core.universal_loader import UniversalLoader
        from src.core.ai_decompiler import AIDecompiler
        try:
            loader = UniversalLoader()
            if not loader.load(self.current_file_path):
                self.decompile_view.setPlainText("[ERROR] Could not load binary for decompilation.")
                return
            parsed = loader.parsed
            sections = getattr(parsed, 'sections', []) if hasattr(parsed, 'sections') else []
            all_code = ""
            for section in sections:
                if hasattr(section, 'name') and section.name.lower() in ['.text', '__text', 'code', 'init', 'main']:
                    content = loader.get_section_content(section.name)
                    if content:
                        from src.core.disassembler import DisassemblerEngine
                        dis = DisassemblerEngine()
                        instructions = dis.disassemble(content, section.virtual_address)
                        for instr in instructions:
                            all_code += f"{instr['mnemonic']} {instr['op_str']}\n"
            if not all_code.strip():
                self.decompile_view.setPlainText("[ERROR] Could not extract assembly for decompilation.")
                return
            self.decompile_view.setPlainText("[INFO] Running AI decompilation...\n(This may take a minute for large binaries)")
            QApplication.processEvents()
            result = ai_decompiler.decompile_assembly(all_code)
            # If AI fails, fallback to RetDec/Ghidra
            if not result or 'decompilation failed' in result.lower() or 'error' in result.lower() or result.strip() == '':
                self.decompile_view.setPlainText("[WARN] AI decompilation failed or incomplete. Falling back to RetDec/Ghidra.")
                retdec_result = self.decompiler_manager._run_retdec(self.current_file_path)
                if retdec_result and 'error' not in retdec_result.lower() and 'failed' not in retdec_result.lower():
                    self.decompile_view.setPlainText(retdec_result)
                else:
                    ghidra_result = self.decompiler_manager._run_ghidra(self.current_file_path)
                    if ghidra_result and 'error' not in ghidra_result.lower() and 'failed' not in ghidra_result.lower():
                        if len(ghidra_result.encode('utf-8')) > MAX_DISPLAY_SIZE or ghidra_result.count('\n') > MAX_DISPLAY_LINES:
                            output_path = os.path.join(os.getcwd(), "output_full_decompile_ghidra.c")
                            with open(output_path, "w", encoding="utf-8", errors="replace") as f:
                                f.write(ghidra_result)
                            self.decompile_view.setPlainText(f"[INFO] Decompiled code too large to display. Saved to {output_path}.")
                            self.log_view.append(f"[INFO] Decompiled code saved to {output_path}.")
                            self.show_open_output_button(output_path)
                            try:
                                import os
                                os.startfile(output_path)
                            except Exception as e:
                                from PyQt6.QtWidgets import QMessageBox
                                QMessageBox.warning(self, "Open Output Failed", f"Could not open output file automatically: {e}")
                        else:
                            self.decompile_view.setPlainText(ghidra_result)
                            self.log_view.append("[INFO] Source Code tab updated with Ghidra C decompilation.")
                    else:
                        self.decompile_view.setPlainText("[ERROR] All decompilation engines failed. Please check logs.")
                        self.log_view.append("[ERROR] All decompilation engines failed.")
            else:
                if len(result.encode('utf-8')) > MAX_DISPLAY_SIZE or result.count('\n') > MAX_DISPLAY_LINES:
                    output_path = os.path.join(os.getcwd(), "output_full_decompile_ai.c")
                    with open(output_path, "w", encoding="utf-8", errors="replace") as f:
                        f.write(result)
                    self.decompile_view.setPlainText(f"[INFO] Decompiled code too large to display. Saved to {output_path}.")
                    self.log_view.append(f"[WARN] Decompiled code too large to display. Saved to {output_path}.")
                    self.show_open_output_button(output_path)
                    # Auto-open the output file for user
                    try:
                        import os
                        os.startfile(output_path)
                    except Exception as e:
                        from PyQt6.QtWidgets import QMessageBox
                        QMessageBox.warning(self, "Open Output Failed", f"Could not open output file automatically: {e}")
                else:
                    self.decompile_view.setPlainText(result)
                    self.log_view.append("[INFO] Decompilation complete")
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            self.source_code_view.setPlainText(f"[ERROR] Full-binary decompilation failed: {e}")
            self.log_view.append(f"[ERROR] Full-binary decompilation failed: {e}")
            QMessageBox.critical(self, "Decompilation Error", f"Full-binary decompilation failed: {e}")

    def on_decompile_complete(self, results):
        # Update AI analysis panel with results
        self.ai_analysis_panel.update_analysis_results(results)
        # Automatically update the Source Code tab with high-level decompiled code
        code = None
        # Try consensus first
        if 'consensus' in results and results['consensus']:
            code = results['consensus']
        # Fallback to LLM or any engine result
        elif isinstance(results, dict):
            for v in results.values():
                if isinstance(v, dict) and v.get('success') and v.get('code'):
                    code = v['code']
                    break
                elif isinstance(v, str) and v.strip():
                    code = v
                    break
        # If code is empty or looks like a failed AI result, fall back to RetDec/Ghidra
        if not code or 'decompilation failed' in code.lower() or 'error' in code.lower() or code.strip() == '':
            self.log_view.append("[WARN] AI decompilation failed or incomplete. Falling back to RetDec/Ghidra.")
            # Try RetDec first
            retdec_result = self.decompiler_manager._run_retdec(self.current_file_path)
            if retdec_result and 'error' not in retdec_result.lower() and 'failed' not in retdec_result.lower():
                self.source_code_view.setPlainText(retdec_result)
                self.log_view.append("[INFO] Source Code tab updated with RetDec C decompilation.")
            else:
                ghidra_result = self.decompiler_manager._run_ghidra(self.current_file_path)
                if ghidra_result and 'error' not in ghidra_result.lower() and 'failed' not in ghidra_result.lower():
                    self.source_code_view.setPlainText(ghidra_result)
                    self.log_view.append("[INFO] Source Code tab updated with Ghidra C decompilation.")
                else:
                    self.source_code_view.setPlainText("[ERROR] All decompilation engines failed. Please check logs.")
                    self.log_view.append("[ERROR] All decompilation engines failed.")
        else:
            self.source_code_view.setPlainText(code)
            self.log_view.append("[INFO] Source Code tab updated with AI decompilation.")
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
        bin_info = results.get('binary_info', {})
        instructions = results.get('instructions', [])
        # Show disassembly or debug info
        if bin_info.get('type', '').lower() == 'unknown':
            self.disassembly_view.setPlainText('[DEBUG] Starting binary analysis...\nUnknown format')
        else:
            # Try to show Ghidra decompilation output in the disassembly view first
            ghidra_result = self.decompiler_manager._run_ghidra(self.current_file_path)
            # DEBUG: Always log the full Ghidra output for troubleshooting
            self.log_view.append('[DEBUG] Raw Ghidra output:\n' + (ghidra_result.strip() if ghidra_result else '[None]'))
            if ghidra_result and 'error' not in ghidra_result.lower() and 'failed' not in ghidra_result.lower() and ghidra_result.strip():
                self.disassembly_view.setPlainText('[GHIDRA C DECOMPILATION OUTPUT]\n' + ghidra_result.strip())
                self.log_view.append('[INFO] Disassembly view updated with Ghidra C decompilation.')
            else:
                # Fallback: Display raw assembly instructions
                if instructions:
                    disasm_text = '\n'.join([
                        f"{instr.get('address', ''):08X}: {instr.get('mnemonic', '')} {instr.get('op_str', '')}".strip()
                        for instr in instructions
                    ])
                    self.disassembly_view.setPlainText(disasm_text)
                    self.log_view.append('[INFO] Disassembly view updated with raw assembly.')
                else:
                    self.disassembly_view.setPlainText('[INFO] No instructions found for this binary.')
                    self.log_view.append('[WARN] No instructions found for this binary.')

        # Start AI decompilation if enabled
        if self.ai_decompile_cb.isChecked():
            assembly_code = "\n".join([
                f"{instr['mnemonic']} {instr['op_str']}"
                for instr in instructions
            ])
            
            self.decompile_worker = DecompileWorker(
                self.decompiler_manager,
                assembly_code,
                self.current_file_path
            )
        self.decompile_worker.decompile_complete.connect(self.on_decompile_complete)
        self.decompile_worker.progress_update.connect(self.update_progress)
        self.decompile_worker.start()
        
        self.progress_bar.setVisible(False)
    def on_decompile_complete(self, results):
        # Update AI analysis panel with results
        self.ai_analysis_panel.update_analysis_results(results)
        # Automatically update the Source Code tab with high-level decompiled code
        code = None
        # Try consensus first
        if 'consensus' in results and results['consensus']:
            code = results['consensus']
        # Fallback to LLM or any engine result
        elif isinstance(results, dict):
            for v in results.values():
                if isinstance(v, dict) and v.get('success') and v.get('code'):
                    code = v['code']
                    break
                elif isinstance(v, str) and v.strip():
                    code = v
                    break
        # If code is empty or looks like a failed AI result, fall back to RetDec/Ghidra
        if not code or 'decompilation failed' in code.lower() or 'error' in code.lower() or code.strip() == '':
            self.log_view.append("[WARN] AI decompilation failed or incomplete. Falling back to RetDec/Ghidra.")
            # Try RetDec first
            retdec_result = self.decompiler_manager._run_retdec(self.current_file_path)
            if retdec_result and 'error' not in retdec_result.lower() and 'failed' not in retdec_result.lower():
                self.source_code_view.setPlainText(retdec_result)
                self.log_view.append("[INFO] Source Code tab updated with RetDec C decompilation.")
            else:
                ghidra_result = self.decompiler_manager._run_ghidra(self.current_file_path)
                if ghidra_result and 'error' not in ghidra_result.lower() and 'failed' not in ghidra_result.lower():
                    self.source_code_view.setPlainText(ghidra_result)
                    self.log_view.append("[INFO] Source Code tab updated with Ghidra C decompilation.")
                else:
                    self.source_code_view.setPlainText("[ERROR] All decompilation engines failed. Please check logs.")
                    self.log_view.append("[ERROR] All decompilation engines failed.")
        else:
            self.source_code_view.setPlainText(code)
            self.log_view.append("[INFO] Source Code tab updated with AI decompilation.")
        self.log_view.append("[INFO] Decompilation complete")

    def on_threat_complete(self, results):
        threat_info = results['results']
        
        # Display threat intelligence results
        threat_text = f"Hash: {results['hash']}\n"
        threat_text += f"Reputation Score: {threat_info.get('reputation_score', 0)}/100\n"
        threat_text += f"Threats Detected: {len(threat_info.get('threats_detected', []))}\n\n"
        
        for source, data in threat_info.get('sources', {}).items():
            threat_text += f"{source.upper()}:\n"
            if 'error' in data:
                threat_text += f"  Error: {data['error']}\n"
            else:
                threat_text += f"  Malicious: {data.get('malicious', False)}\n"
                threat_text += f"  Confidence: {data.get('confidence', 0)}%\n"
            threat_text += "\n"
        
        self.threat_results_view.setPlainText(threat_text)
        self.log_view.append("[INFO] Threat intelligence analysis complete")

    def extract_basic_blocks(self, instructions):
        """Extract basic blocks from instructions for CFG visualization"""
        basic_blocks = []
        current_block = []
        current_address = None
        
        for instr in instructions:
            if current_address is None:
                current_address = instr['address']
            
            current_block.append(instr)
            
            # End block on control flow instructions
            mnemonic = instr['mnemonic'].lower()
            if any(x in mnemonic for x in ['jmp', 'je', 'jne', 'call', 'ret']):
                if current_block:
                    basic_blocks.append({
                        'address': current_address,
                        'size': len(current_block),
                        'instructions': current_block,
                        'targets': []  # Would need more analysis for real targets
                    })
                current_block = []
                current_address = None
        
        # Add remaining block
        if current_block:
            basic_blocks.append({
                'address': current_address,
                'size': len(current_block),
                'instructions': current_block,
                'targets': []
            })
        
        return basic_blocks

    def update_progress(self, message):
        self.analysis_status.setText(message)
        self.log_view.append(f"[PROGRESS] {message}")

    def save_openai_api_key(self):
        # Save the OpenAI API key from the settings panel
        api_key = self.api_key_edit.text().strip()
        if api_key:
            self.log_view.append("[INFO] OpenAI API key saved for this session.")
        else:
            self.log_view.append("[WARN] No API key entered.")

    def summarize_function_with_ai(self):
        # Summarize the displayed function/code with AI
        try:
            from src.ai.assistant import AIAssistant
            import subprocess
            model_name = self.model_combo.currentText()
            code = self.ai_analysis_panel.llm_view.toPlainText()
            if not code:
                self.log_view.append("[ERROR] No code to summarize.")
                return
            if model_name == "OpenAI GPT-4":
                # WARNING: Hardcoded OpenAI API key for development/testing only. REMOVE BEFORE SHARING OR DEPLOYMENT.
                api_key = self.api_key_edit.text().strip() if hasattr(self, 'api_key_edit') else ''
                if not api_key:
                    api_key = "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"
                assistant = AIAssistant(api_key=api_key, model="gpt-4")
                prompt = f"Summarize the following decompiled function or code for a reverse engineer. Highlight its purpose, logic, and any security-relevant operations.\n\n{code}"
                try:
                    response = assistant.client.chat.completions.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": "You are an expert reverse engineer and code summarizer."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=800,
                        temperature=0.3
                    )
                    summary = response.choices[0].message.content
                    self.ai_analysis_panel.consensus_view.setPlainText(summary)
                    self.log_view.append("[INFO] AI function/code summary complete.")
                except Exception as e:
                    self.log_view.append(f"[ERROR] AI summarization failed: {e}")
            elif model_name == "Ollama (Local)":
                max_chars = 2000
                safe_code = code[:max_chars]
                prompt = f"Summarize this decompiled code for a reverse engineer. Highlight its purpose, logic, and any security-relevant operations.\n\n{safe_code}"
                try:
                    result = subprocess.run([
                        "ollama", "run", "llama3", prompt
                    ], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
                    if result.returncode == 0:
                        self.ai_analysis_panel.consensus_view.setPlainText(result.stdout.strip())
                        self.log_view.append("[INFO] Ollama: AI function/code summary complete.")
                    else:
                        self.log_view.append(f"[ERROR] Ollama summarization failed: {result.stderr.strip()}")
                except UnicodeDecodeError as ude:
                    self.log_view.append(f"[ERROR] UnicodeDecodeError: {ude}. This is likely due to non-UTF8 output from a subprocess. Try setting PYTHONIOENCODING=utf-8 in your environment.")
                except subprocess.TimeoutExpired:
                    self.log_view.append("[ERROR] Ollama timed out while summarizing code. Try a smaller function or code block.")
                except Exception as e:
                    self.log_view.append(f"[ERROR] Ollama not available or failed: {e}")
            else:
                self.log_view.append("[INFO] Summarization is only available with OpenAI GPT-4 or Ollama (Local) model.")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to summarize with AI: {e}")

    def export_ai_results(self):
        """
        Export the contents of all AI Analysis Panel tabs to a text file.
        """
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Export AI Results", "", "Text Files (*.txt)")
            if file_path:
                llm_code = self.ai_analysis_panel.llm_view.toPlainText()
                traditional_code = self.ai_analysis_panel.traditional_view.toPlainText()
                consensus = self.ai_analysis_panel.consensus_view.toPlainText()
                comparison = self.ai_analysis_panel.comparison_view.toPlainText()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# LLM4Decompile Result\n\n" + llm_code + "\n\n")
                    f.write("# Traditional Decompilation\n\n" + traditional_code + "\n\n")
                    f.write("# Consensus\n\n" + consensus + "\n\n")
                    f.write("# Comparison\n\n" + comparison + "\n")
                self.log_view.append(f"[INFO] AI results exported to {file_path}")
        except Exception as e:
            self.log_view.append(f"[ERROR] Failed to export AI results: {e}")

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Open Binary File", 
            "", 
            "All Files (*);; Executables (*.exe *.dll);; Python Bytecode (*.pyc)"
        )
        if file_path:
            self.load_binary(file_path)

    def load_binary(self, file_path):
        self.current_file_path = file_path
        if hasattr(self, 'file_label'):
            self.file_label.setText(f"File: {file_path}")
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
        # Clear previous results
        if hasattr(self, 'binary_info_tree'):
            self.binary_info_tree.clear()
        if hasattr(self, 'disassembly_view'):
            self.disassembly_view.clear()
        if hasattr(self, 'threat_results_view'):
            self.threat_results_view.clear()
        if hasattr(self, 'ioc_list'):
            self.ioc_list.clear()
        if hasattr(self, 'log_view'):
            self.log_view.append(f"[INFO] Loading binary: {file_path}")
        # Start binary analysis
        self.analysis_worker = BinaryAnalysisWorker(
            self.binary_loader, 
            self.disassembler, 
            file_path
        )
        self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_worker.progress_update.connect(self.update_progress)
        self.analysis_worker.start()
        # Start threat intelligence analysis if enabled
        if hasattr(self, 'threat_intel_cb') and self.threat_intel_cb.isChecked():
            self.threat_worker = ThreatAnalysisWorker(file_path, self.threat_intel)
            self.threat_worker.threat_complete.connect(self.on_threat_complete)
            self.threat_worker.progress_update.connect(self.update_progress)
            self.threat_worker.start()


    def show_open_output_button(self, output_path):
        # Show a button in the current view to open the output file externally
        btn = QPushButton(f"Open output file: {os.path.basename(output_path)}")
        btn.clicked.connect(lambda: os.startfile(output_path))
        # Try to add to the currently focused tab
        current_widget = self.analysis_tabs.currentWidget()
        if isinstance(current_widget, QWidget):
            layout = current_widget.layout()
            if layout:
                layout.addWidget(btn)
        self.log_view.append(f"[INFO] Provided button to open {output_path}")

    def export_analysis(self):
        if not self.current_file_path:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Analysis Results", "", "JSON Files (*.json)"
        )
        if file_path:
            # Export functionality would be implemented here
            self.log_view.append(f"[INFO] Analysis exported to {file_path}")

    def reanalyze_with_ai(self):
        """Re-run AI decompilation on the currently loaded binary/code."""
        if not self.current_file_path:
            self.log_view.append("[ERROR] No file loaded for AI re-analysis.")
            return
        # Try to get instructions from the disassembly view or last analysis
        instructions = []
        # If you have a way to cache or store the last instructions, use that.
        # Here, we'll try to parse from the disassembly view as a fallback.
        disasm_text = self.disassembly_view.toPlainText()
        if not disasm_text.strip():
            self.log_view.append("[ERROR] No disassembly available for AI re-analysis.")
            return
        # Parse instructions (naive split, assumes one per line: 'mnemonic operands')
        lines = disasm_text.strip().splitlines()
        parsed_instructions = []
        for line in lines:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                parsed_instructions.append({'mnemonic': parts[0], 'op_str': parts[1]})
            elif len(parts) == 1:
                parsed_instructions.append({'mnemonic': parts[0], 'op_str': ''})
        if not parsed_instructions:
            self.log_view.append("[ERROR] Could not parse instructions for AI re-analysis.")
            return
        assembly_code = "\n".join([
            f"{instr['mnemonic']} {instr['op_str']}".strip()
            for instr in parsed_instructions
        ])
        self.decompile_worker = DecompileWorker(
            self.decompiler_manager,
            assembly_code,
            self.current_file_path
        )
        self.decompile_worker.decompile_complete.connect(self.on_decompile_complete)
        self.decompile_worker.progress_update.connect(self.update_progress)
        self.decompile_worker.start()
        self.log_view.append("[INFO] Started AI re-decompilation of current binary/code.")

    def enhance_with_ai_comments(self):
        """Enhance the decompiled code with AI-generated comments (stub)."""
        self.log_view.append("[INFO] Enhance with AI comments triggered (not implemented yet).")

    def ask_ai_about_code(self):
        """Answer user questions about the code using AI (stub)."""
        self.log_view.append("[INFO] Ask AI about code triggered (not implemented yet).")

    def configure_misp(self):
        """Open the MISP configuration dialog (stub)."""
        self.log_view.append("[INFO] Configure MISP triggered (not implemented yet).")

    def export_iocs(self):
        # IOC export functionality would be implemented here
        self.log_view.append("[INFO] IOC export (to be implemented)")
