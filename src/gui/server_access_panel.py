"""Server Access tab — direct API entry using captured credentials (app-independent)."""

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget, QComboBox,
    QTextEdit,
)


class ServerAccessPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        from src.core.server_access import DirectAccessSession
        self._session = DirectAccessSession()
        self._flows = []
        self._base_url = ""
        self._app_name = ""
        self._creds = []
        self._poll = QTimer(self)
        self._poll.setInterval(20_000)
        self._poll.timeout.connect(self._on_poll)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        head = QLabel("Direct Server Access")
        head.setObjectName("Heading")
        layout.addWidget(head)
        hint = QLabel(
            "After capture finds an endpoint and session token, establish direct API access. "
            "Calls continue even when the target app is quit — proving independent server entry.")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.status_label = QLabel("Status: Waiting for captured credentials…")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        row = QHBoxLayout()
        self.cred_combo = QComboBox()
        self.cred_combo.setMinimumWidth(280)
        row.addWidget(self.cred_combo, 1)
        self.establish_btn = QPushButton("Establish Direct Access")
        self.establish_btn.setObjectName("Primary")
        self.establish_btn.clicked.connect(self._establish)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)
        row.addWidget(self.establish_btn)
        row.addWidget(self.stop_btn)
        layout.addLayout(row)

        self.report = QTextEdit()
        self.report.setReadOnly(True)
        layout.addWidget(self.report, 1)

    def update_from_capture(self, flows, base_url: str = "", app_name: str = ""):
        self._flows = list(flows or [])
        if base_url:
            self._base_url = base_url
        if app_name:
            self._app_name = app_name
        self._creds = self._session.configure(
            flows=self._flows,
            base_url=self._base_url,
            app_name=self._app_name,
        )
        self.cred_combo.blockSignals(True)
        self.cred_combo.clear()
        for c in self._creds[:12]:
            from src.core.server_access import mask_credential
            self.cred_combo.addItem(
                f"[{c.cred_type}] {mask_credential(c.value)}  ({c.host or 'capture'})",
                c,
            )
        self.cred_combo.blockSignals(False)
        if self._creds and not self._session.state.active:
            self.status_label.setText(
                f"Ready — {len(self._creds)} credential(s) harvested. "
                "Click Establish Direct Access, then quit the app to prove independent entry.")
        self._refresh_report()

    def _selected_cred(self):
        idx = self.cred_combo.currentIndex()
        if idx >= 0:
            return self.cred_combo.itemData(idx)
        return self._creds[0] if self._creds else None

    def _establish(self):
        cred = self._selected_cred()
        if not cred and not self._flows:
            self.status_label.setText("Capture traffic first — send a message in the app while Network Capture runs.")
            return
        self._session.configure(
            flows=self._flows,
            base_url=self._base_url,
            app_name=self._app_name,
            credential=cred,
        )
        out = self._session.establish()
        if not out.get("ok"):
            self.status_label.setText(out.get("reason", "Failed"))
            self._refresh_report()
            return
        proven = out.get("proven")
        self.status_label.setText(
            "ACCESS PROVEN — direct server calls active. Quit the app to demonstrate independent access."
            if proven else
            "Live — polling server (awaiting proof). Quit the app to demonstrate independent access.")
        self.establish_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._poll.start()
        self._refresh_report()

    def _stop(self):
        self._session.stop()
        self._poll.stop()
        self.establish_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Stopped.")
        self._refresh_report()

    def _on_poll(self):
        rec = self._session.tick()
        if rec and rec.independent:
            self.status_label.setText(
                f"✓ INDEPENDENT ACCESS — {self._session.state.calls_while_app_closed} "
                f"call(s) while {self._app_name or 'app'} is CLOSED. Server entry proven.")
        elif self._session.state.access_proven and not rec.app_running if rec else False:
            self.status_label.setText("App closed — direct server access continuing.")
        self._refresh_report()

    def _refresh_report(self):
        self.report.setPlainText(self._session.state.format_report())
