import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from src.core.universal_loader import UniversalLoader
from src.core.unpacker import BasicUnpacker
from src.core.decompiler_manager import DecompilerManager
from src.core.advanced_unpacking import AdvancedUnpacker

class FolderAnalysisWorker(QThread):
    progress_update = pyqtSignal(str)
    analysis_complete = pyqtSignal(dict)

    def __init__(self, folder_path):
        super().__init__()
        self.folder_path = folder_path
        self.decompiler_manager = DecompilerManager()

    def run(self):
        from src.core.bundle_analysis import analyze_binary_file, render_summary, summarize_bundle
        result_tree = {}
        for root, dirs, files in os.walk(self.folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.folder_path)
                summary = analyze_binary_file(file_path)
                summary['summary_text'] = render_summary(summary)
                # Include source code inline for quick viewing.
                if summary.get('kind') == 'source':
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                            summary['code'] = fh.read()
                    except Exception as e:
                        summary['code'] = f"[ERROR] {e}"
                result_tree[rel_path] = summary
                self.progress_update.emit(f"Analyzed: {rel_path}")
        result_tree['__bundle_summary__'] = summarize_bundle(result_tree)
        self.analysis_complete.emit(result_tree)

class FullSoftwarePanel(QWidget):
    def advanced_unpack_selected(self):
        if not self.last_selected_path:
            self.viewer.setPlainText('[ERROR] No file selected for advanced unpacking.')
            return
        abs_path = os.path.join(getattr(self.analysis_worker, 'folder_path', ''), self.last_selected_path)
        if not os.path.isfile(abs_path):
            self.viewer.setPlainText('[ERROR] Selected item is not a file.')
            return
        results = []
        # 1. DIE packer detection
        try:
            packer_info = self.adv_unpacker.detect_packer(abs_path)
            results.append(f'[PACKER INFO]\n{packer_info.strip() if packer_info else "None"}')
        except Exception as e:
            results.append(f'[PACKER INFO]\n[ERROR] {e}')
        # 2. Entropy analysis
        try:
            entropy = self.adv_unpacker.entropy_analysis(abs_path)
            results.append(f'[ENTROPY] {entropy:.2f}')
        except Exception as e:
            results.append(f'[ENTROPY]\n[ERROR] {e}')
        # 3. Static anti-debug patching (stub)
        try:
            patched = self.adv_unpacker.static_patch_antidebug(abs_path)
            results.append(f'[STATIC PATCH ANTI-DEBUG]\n{patched}')
        except Exception as e:
            results.append(f'[STATIC PATCH ANTI-DEBUG]\n[ERROR] {e}')
        # 4. Frida dynamic instrumentation (stub)
        try:
            frida_result = self.adv_unpacker.run_frida_script(abs_path, "// stub script")
            results.append(f'[FRIDA DYNAMIC INSTRUMENTATION]\n{frida_result}')
        except Exception as e:
            results.append(f'[FRIDA DYNAMIC INSTRUMENTATION]\n[ERROR] {e}')
        # 5. Qiling emulation (stub)
        try:
            qiling_result = self.adv_unpacker.run_qiling(abs_path)
            results.append(f'[QILING EMULATION]\n{qiling_result}')
        except Exception as e:
            results.append(f'[QILING EMULATION]\n[ERROR] {e}')
        # 6. angr symbolic execution (stub)
        try:
            angr_result = self.adv_unpacker.angr_symbolic_exec(abs_path)
            results.append(f'[ANGR SYMBOLIC EXECUTION]\n{angr_result}')
        except Exception as e:
            results.append(f'[ANGR SYMBOLIC EXECUTION]\n[ERROR] {e}')
        # 7. Brute-force XOR decryption
        try:
            with open(abs_path, 'rb') as f:
                data = f.read()
            xor_results = self.adv_unpacker.brute_force_xor(data)
            if xor_results:
                import tempfile  # os is imported at module level
                xor_sections = []
                for r in xor_results:
                    section = f"Key {r['key']}: Format: {r['format']} | Language: {r['high_level']}\nSnippet:\n{r['snippet']}"
                    # If looks like PE/ELF/EXE, try Ghidra on decrypted blob
                    if r['format'] in ('PE/EXE', 'ELF'):
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tf:
                                tf.write(bytes([b ^ r['key'] for b in data]))
                                tf.flush()
                                ghidra_result = self.decompiler_manager._run_ghidra(tf.name)
                            if ghidra_result and not ghidra_result.lower().startswith('ghidra error'):
                                section += f"\n[Ghidra Decompiled C]\n{ghidra_result.strip()}"
                            else:
                                section += f"\n[Ghidra Decompiled C]\n[ERROR] {ghidra_result}"
                            os.unlink(tf.name)
                        except Exception as e:
                            section += f"\n[Ghidra Decompiled C]\n[ERROR] {e}"
                    xor_sections.append(section + f"\n{'-'*40}")
                xor_str = '\n'.join(xor_sections)
                results.append(f'[BRUTE-FORCE XOR]\n{xor_str}')
            else:
                results.append(f'[BRUTE-FORCE XOR]\nNo XOR-encrypted code found.')
        except Exception as e:
            results.append(f'[BRUTE-FORCE XOR]\n[ERROR] {e}')
        # 8. Runtime dump (stub)
        try:
            dump_result = self.adv_unpacker.dump_sections_after_runtime(abs_path)
            results.append(f'[RUNTIME MEMORY DUMP]\n{dump_result}')
        except Exception as e:
            results.append(f'[RUNTIME MEMORY DUMP]\n[ERROR] {e}')
        # Show all results
        self.viewer.setPlainText('\n\n'.join(str(r) for r in results))

    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.folder_btn = QPushButton("Select Folder for Full Software Analysis")
        self.folder_btn.clicked.connect(self.select_folder)
        self.layout.addWidget(self.folder_btn)
        self.adv_unpack_btn = QPushButton("Advanced Unpack/Bypass Selected File")
        self.adv_unpack_btn.clicked.connect(self.advanced_unpack_selected)
        self.layout.addWidget(self.adv_unpack_btn)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.layout.addWidget(self.progress)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["File/Folder"])
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.viewer = QTextEdit()
        self.viewer.setReadOnly(True)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.viewer)
        self.layout.addWidget(self.splitter)
        self.analysis_results = {}
        self.adv_unpacker = AdvancedUnpacker()
        self.last_selected_path = None

    def advanced_unpack_selected(self):
        if not self.last_selected_path:
            self.viewer.setPlainText('[ERROR] No file selected for advanced unpacking.')
            return
        abs_path = os.path.join(getattr(self.analysis_worker, 'folder_path', ''), self.last_selected_path)
        if not os.path.isfile(abs_path):
            self.viewer.setPlainText('[ERROR] Selected item is not a file.')
            return
        results = []
        # 1. DIE packer detection
        try:
            packer_info = self.adv_unpacker.detect_packer(abs_path)
            results.append(f'[PACKER INFO]\n{packer_info.strip() if packer_info else "None"}')
        except Exception as e:
            results.append(f'[PACKER INFO]\n[ERROR] {e}')
        # 2. Entropy analysis
        try:
            entropy = self.adv_unpacker.entropy_analysis(abs_path)
            results.append(f'[ENTROPY] {entropy:.2f}')
        except Exception as e:
            results.append(f'[ENTROPY]\n[ERROR] {e}')
        # 3. Static anti-debug patching (stub)
        try:
            patched = self.adv_unpacker.static_patch_antidebug(abs_path)
            results.append(f'[STATIC PATCH ANTI-DEBUG]\n{patched}')
        except Exception as e:
            results.append(f'[STATIC PATCH ANTI-DEBUG]\n[ERROR] {e}')
        # 4. Frida dynamic instrumentation (stub)
        try:
            frida_result = self.adv_unpacker.run_frida_script(abs_path, "// stub script")
            results.append(f'[FRIDA DYNAMIC INSTRUMENTATION]\n{frida_result}')
        except Exception as e:
            results.append(f'[FRIDA DYNAMIC INSTRUMENTATION]\n[ERROR] {e}')
        # 5. Qiling emulation (stub)
        try:
            qiling_result = self.adv_unpacker.run_qiling(abs_path)
            results.append(f'[QILING EMULATION]\n{qiling_result}')
        except Exception as e:
            results.append(f'[QILING EMULATION]\n[ERROR] {e}')
        # 6. angr symbolic execution (stub)
        try:
            angr_result = self.adv_unpacker.angr_symbolic_exec(abs_path)
            results.append(f'[ANGR SYMBOLIC EXECUTION]\n{angr_result}')
        except Exception as e:
            results.append(f'[ANGR SYMBOLIC EXECUTION]\n[ERROR] {e}')
        # 7. Brute-force XOR decryption
        try:
            with open(abs_path, 'rb') as f:
                data = f.read()
            xor_results = self.adv_unpacker.brute_force_xor(data)
            if xor_results:
                xor_str = '\n'.join([f'Key {key}: {decrypted[:32].hex()}...' for key, decrypted in xor_results[:5]])
                results.append(f'[BRUTE-FORCE XOR]\n{xor_str}')
            else:
                results.append(f'[BRUTE-FORCE XOR]\nNo XOR-encrypted MZ/PE found.')
        except Exception as e:
            results.append(f'[BRUTE-FORCE XOR]\n[ERROR] {e}')
        # 8. Runtime dump (stub)
        try:
            dump_result = self.adv_unpacker.dump_sections_after_runtime(abs_path)
            results.append(f'[RUNTIME MEMORY DUMP]\n{dump_result}')
        except Exception as e:
            results.append(f'[RUNTIME MEMORY DUMP]\n[ERROR] {e}')
        # Show all results
        self.viewer.setPlainText('\n\n'.join(str(r) for r in results))

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Software Folder")
        if folder:
            self.progress.setVisible(True)
            self.progress.setRange(0, 0)
            self.tree.clear()
            self.viewer.clear()
            self.analysis_worker = FolderAnalysisWorker(folder)
            self.analysis_worker.progress_update.connect(self.update_progress)
            self.analysis_worker.analysis_complete.connect(self.on_analysis_complete)
            self.analysis_worker.start()

    def update_progress(self, msg):
        self.progress.setFormat(msg)

    def on_analysis_complete(self, results):
        self.progress.setVisible(False)
        self.bundle_summary = results.pop('__bundle_summary__', '')
        self.analysis_results = results
        self.populate_tree()
        if self.bundle_summary:
            self.viewer.setPlainText(self.bundle_summary +
                                     "\n\n(Select a file on the left for its details.)")

    def populate_tree(self):
        self.tree.clear()
        paths = [p for p in self.analysis_results.keys() if p != '__bundle_summary__']
        root_items = {}
        for path in paths:
            parts = path.split(os.sep)
            parent = None
            for i, part in enumerate(parts):
                sub_path = os.sep.join(parts[:i+1])
                if sub_path not in root_items:
                    item = QTreeWidgetItem([part])
                    if parent is None:
                        self.tree.addTopLevelItem(item)
                    else:
                        parent.addChild(item)
                    root_items[sub_path] = item
                parent = root_items[sub_path]
        self.tree.expandAll()

    def on_item_clicked(self, item):
        # Build the relative path from the tree
        path = []
        node = item
        while node is not None:
            path.insert(0, node.text(0))
            node = node.parent()
        rel_path = os.sep.join(path)
        self.last_selected_path = rel_path
        result = self.analysis_results.get(rel_path, {})
        parts = []
        if 'summary_text' in result:
            parts.append(result['summary_text'])
        if 'code' in result:
            parts.append("\n----- SOURCE -----\n" + result['code'])
        if not parts:
            parts.append('[No analysis available for this file]')
        self.viewer.setPlainText("\n\n".join(parts))

