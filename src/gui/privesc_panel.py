"""Privilege-Escalation surface panel — static attack-surface map of a binary.

Pure analysis: it calls src/core/privesc_surface.analyze() and renders the
findings. It never executes the target.
"""

from PyQt6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from src.core import privesc_surface as ps


class PrivescPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("Privilege-Escalation Attack Surface")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)

        note = QLabel(
            "Static map of privilege-escalation weaknesses: setuid/setgid, world-writable "
            "binaries, risky entitlements, dylib-hijack load paths, and shell/identity "
            "imports. Concrete weak points — not a working exploit. Never executes the target.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        layout.addWidget(note)

        row = QHBoxLayout()
        self.analyze_loaded_btn = QPushButton("Analyze Loaded Binary")
        self.analyze_loaded_btn.setObjectName("Primary")
        self.analyze_loaded_btn.clicked.connect(self.analyze_loaded)
        self.pick_btn = QPushButton("Analyze a File…")
        self.pick_btn.clicked.connect(self.pick_file)
        row.addWidget(self.analyze_loaded_btn)
        row.addWidget(self.pick_btn)
        row.addStretch()
        layout.addLayout(row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self._target = None

    def set_target(self, path):
        """Called by the main window when a binary is loaded."""
        self._target = path

    def analyze_loaded(self):
        if not self._target:
            self.output.setPlainText(
                "No binary loaded. Open one from the main window, or use 'Analyze a File…'.")
            return
        self._run(self._target)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a binary to analyze")
        if path:
            self._run(path)

    def _run(self, path):
        try:
            findings = ps.analyze(path)
            self.output.setPlainText(ps.format_report(findings, path))
        except Exception as e:
            self.output.setPlainText(f"[ERROR] {e}")
