"""Evidence Chain panel — fusion graph of all collected evidence."""

from PyQt6.QtWidgets import QVBoxLayout, QLabel, QTextEdit, QPushButton, QWidget, QFileDialog


class EvidenceChainPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows = []
        self._probe_results = []
        layout = QVBoxLayout(self)
        hint = QLabel(
            "Architecture findings fused from STATIC, LIVE traffic, response headers, "
            "probes, and inference — confidence grows as independent layers converge.")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText("Evidence appears as analysis runs.")
        layout.addWidget(self.report, 1)
        btn_row = QVBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.export_btn = QPushButton("Export HTML Report")
        self.export_btn.clicked.connect(self._export)
        btn_row.addWidget(self.refresh_btn)
        btn_row.addWidget(self.export_btn)
        layout.addLayout(btn_row)

    def set_live_context(self, flows=None, probe_results=None):
        if flows is not None:
            self._flows = list(flows)
        if probe_results is not None:
            self._probe_results = list(probe_results)

    def refresh(self):
        from src.core.evidence_store import session_store
        store = session_store()
        self.report.setPlainText(store.format_report(
            flows=self._flows,
            probe_results=self._probe_results,
        ))

    def _export(self):
        from src.core.engagement_report import save_report
        path, _ = QFileDialog.getSaveFileName(self, "Export Report", "engagement_report.html",
                                              "HTML (*.html)")
        if path:
            from src.core import behavior_infer
            save_report(path, behavior_infer_text=behavior_infer.format_report([]))
            self.report.append(f"\n[Exported to {path}]")
