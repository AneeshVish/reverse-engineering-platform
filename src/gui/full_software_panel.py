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
        from src.core.bundle_analysis import analyze_application, render_summary, summarize_bundle
        self.progress_update.emit("Walking application (recursing into archives)...")
        # analyze_application recurses into archives (apk/jar/ipa/zip/tar/...).
        result_tree = analyze_application(self.folder_path)
        for rel_path, summary in result_tree.items():
            summary['summary_text'] = render_summary(summary)
            if summary.get('kind') == 'source':
                p = summary.get('path')
                try:
                    with open(p, 'r', encoding='utf-8', errors='replace') as fh:
                        summary['code'] = fh.read()
                except Exception as e:
                    summary['code'] = f"[ERROR] {e}"
            self.progress_update.emit(f"Analyzed: {rel_path}")
        result_tree['__bundle_summary__'] = summarize_bundle(result_tree)
        self.analysis_complete.emit(result_tree)

class FullSoftwarePanel(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.folder_btn = QPushButton("Select Folder for Full Software Analysis")
        self.folder_btn.clicked.connect(self.select_folder)
        self.layout.addWidget(self.folder_btn)
        self.adv_unpack_btn = QPushButton("Reveal Contents of Selected File")
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
        """Reveal the ACTUAL recoverable contents of the selected file.

        Honest extraction: decodes property lists, decompresses gzip/zlib/bz2/xz,
        lists zip/binary sections, extracts strings, and decodes base64/hex blobs.
        It does NOT pretend to "decrypt" one-way hashes — nothing can.
        """
        if not self.last_selected_path:
            self.viewer.setPlainText('[ERROR] No file selected.')
            return
        abs_path = os.path.join(getattr(self.analysis_worker, 'folder_path', ''),
                                self.last_selected_path)
        if not os.path.isfile(abs_path):
            self.viewer.setPlainText('[ERROR] Selected item is not a file.')
            return
        out = []
        try:
            out.append(self.adv_unpacker.reveal_contents(abs_path))
        except Exception as e:
            out.append(f'[REVEAL] [ERROR] {e}')
        # Packer/protection — only meaningful for PE files; suppress the noise
        # ("Not a PE file." / "PEiD detection failed") on Mach-O/ELF/resources.
        try:
            packer = self.adv_unpacker.detect_packer(abs_path)
            noise = (not packer or packer.startswith(('Not a PE file', 'PEiD detection failed',
                                                      'pefile not installed')))
            if not noise:
                out.append(f'\n[PACKER]\n{packer.strip()}')
        except Exception:
            pass
        # XOR brute-force only matters if it actually finds an embedded format.
        try:
            with open(abs_path, 'rb') as f:
                data = f.read(2 * 1024 * 1024)
            xor = self.adv_unpacker.brute_force_xor(data)
            real = [r for r in xor if r.get('format') not in (None, 'ASCII text?')]
            if real:
                lines = [f"  key=0x{r['key']:02x}: {r['format']} ({r['high_level']})"
                         for r in real[:10]]
                out.append('\n[XOR-DECRYPTED EMBEDDED CODE]\n' + '\n'.join(lines))
        except Exception:
            pass
        self.viewer.setPlainText('\n'.join(out))

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Software Folder")
        if folder:
            self.analyze_folder(folder)

    def analyze_folder(self, folder):
        """Start whole-application analysis on a folder/bundle/archive path."""
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
        folder = getattr(self.analysis_worker, 'folder_path', '')
        # Architecture intelligence report (RED TEAM L1)
        try:
            from src.core import client_architecture_intel as cai
            self._arch_intel = cai.analyze_path(folder)
            cai.to_evidence(self._arch_intel)
            arch_report = cai.format_report(self._arch_intel)
            from src.core.target_profile import session_profile
            session_profile().merge_architecture_intel(self._arch_intel)
        except Exception as e:
            arch_report = f"[Architecture intel error: {e}]"
            self._arch_intel = {}
        if self.bundle_summary:
            self.viewer.setPlainText(self.bundle_summary +
                                     "\n\n" + arch_report +
                                     "\n\n(Select a file on the left for its details.)")
        else:
            self.viewer.setPlainText(arch_report)

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

