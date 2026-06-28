"""Threat-Resistance Lab panel — deploy benign ATT&CK simulations and score them.

The actual simulations run off the UI thread (they create/clean a sandbox). This
panel only builds the request and renders the scoreboard; all safety guarantees
live in src/core/threat_lab.py.
"""

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton,
    QScrollArea, QTextEdit, QVBoxLayout, QWidget,
)

from src.core import threat_lab as tl


class ThreatLabWorker(QThread):
    done = pyqtSignal(list)

    def __init__(self, selected_ids):
        super().__init__()
        self.selected_ids = selected_ids

    def run(self):
        self.done.emit(tl.run_suite(self.selected_ids))


class ThreatLabPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("Threat-Resistance Lab — MITRE ATT&CK simulations")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)

        note = QLabel(
            "Benign simulations only (EICAR / Atomic-Red-Team style). Each runs in a "
            "temporary sandbox that is auto-deleted, uses no real malware payload, "
            "beacons only to a localhost sink, and touches no real user data. Tests run "
            "against THIS host — testing any other system requires written authorization.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        layout.addWidget(note)

        # Technique checklist (from the engine registry — single source of truth).
        self.checks = {}
        holder = QFrame()
        hl = QVBoxLayout(holder)
        for attack_id, name, tactic, severity, _fn in tl.TECHNIQUES:
            cb = QCheckBox(f"{attack_id}   {name}   ·   {tactic} ({severity})")
            cb.setChecked(True)
            self.checks[attack_id] = cb
            hl.addWidget(cb)
        hl.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(holder)
        scroll.setMaximumHeight(240)
        layout.addWidget(scroll)

        row = QHBoxLayout()
        self.run_btn = QPushButton("Deploy Selected Techniques")
        self.run_btn.setObjectName("Primary")
        self.run_btn.clicked.connect(self.run_selected)
        self.all_btn = QPushButton("Select All")
        self.all_btn.clicked.connect(self.select_all)
        self.none_btn = QPushButton("Clear")
        self.none_btn.clicked.connect(self.select_none)
        row.addWidget(self.run_btn)
        row.addWidget(self.all_btn)
        row.addWidget(self.none_btn)
        row.addStretch()
        layout.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.worker = None

    def select_all(self):
        for cb in self.checks.values():
            cb.setChecked(True)

    def select_none(self):
        for cb in self.checks.values():
            cb.setChecked(False)

    def run_selected(self):
        ids = [aid for aid, cb in self.checks.items() if cb.isChecked()]
        if not ids:
            self.output.setPlainText("Select at least one technique to deploy.")
            return
        self.run_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.output.setPlainText("Deploying simulations in a temporary sandbox…")
        self.worker = ThreatLabWorker(ids)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_done(self, results):
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)
        self.output.setPlainText(tl.format_scoreboard(results))
