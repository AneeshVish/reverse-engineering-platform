"""Network Traffic Capture — decrypted, app-targeted HTTPS interception.

Not a packet sniffer. You point it at an app (the loaded binary, or any app/CLI
tool), it launches that app through a local mitmproxy with the CA trusted via env
vars, and shows — in real time, structured — every API call the app makes:
method + URL, request/response headers and bodies, and any API keys / tokens /
secrets found in them. Proves you can capture the real traffic, not just IPs.
"""

import json
import os
import tempfile
import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QFileDialog,
    QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QSpinBox,
    QHeaderView, QAbstractItemView,
)

from src.core import traffic_capture as tc
from src.gui.icons import icon as qicon


class NetworkCapturePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.flows = []
        self._proxy_proc = None
        self._app_proc = None
        self._cap_file = None
        self._offset = 0
        self._all_secrets = []
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tail)
        self._build_ui()

    # -- UI ------------------------------------------------------------------

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Live API Capture")
        title.setObjectName("Heading")
        layout.addWidget(title)
        info = QLabel(
            "Launches the target app through a local HTTPS interceptor and shows its "
            "real API calls, headers, bodies, and any API keys/tokens — decrypted.")
        info.setObjectName("Dim")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Controls.
        row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Target app / binary / CLI tool (defaults to the loaded file)")
        row.addWidget(self.target_edit, 1)
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        row.addWidget(QLabel("Port"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1025, 65535)
        self.port_spin.setValue(8080)
        row.addWidget(self.port_spin)
        layout.addLayout(row)

        row2 = QHBoxLayout()
        self.start_btn = QPushButton("  Capture & Launch App")
        self.start_btn.setObjectName("Primary")
        self.start_btn.setIcon(qicon("fa5s.play"))
        self.start_btn.clicked.connect(self.start_capture)
        self.test_btn = QPushButton("  Run Test Request")
        self.test_btn.setIcon(qicon("fa5s.vial"))
        self.test_btn.clicked.connect(self.run_test_request)
        self.stop_btn = QPushButton("  Stop")
        self.stop_btn.setIcon(qicon("fa5s.stop"))
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        row2.addWidget(self.start_btn)
        row2.addWidget(self.test_btn)
        row2.addWidget(self.stop_btn)
        row2.addStretch()
        self.status = QLabel("Idle")
        self.status.setObjectName("Dim")
        row2.addWidget(self.status)
        layout.addLayout(row2)

        # Main split: flow table (left) | detail (right).
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Method", "Host", "Path", "Status", "Keys"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        split.addWidget(self.table)

        self.detail = QTabWidget()
        self.req_view = QTextEdit(); self.req_view.setReadOnly(True)
        self.resp_view = QTextEdit(); self.resp_view.setReadOnly(True)
        self.flow_secrets = QTextEdit(); self.flow_secrets.setReadOnly(True)
        self.detail.addTab(self.req_view, "Request")
        self.detail.addTab(self.resp_view, "Response")
        self.detail.addTab(self.flow_secrets, "Secrets")
        split.addWidget(self.detail)
        split.setSizes([620, 620])
        layout.addWidget(split, 1)

        # Aggregated secrets across all flows.
        sec_label = QLabel("All Captured API Keys / Tokens / Secrets")
        sec_label.setObjectName("Heading")
        layout.addWidget(sec_label)
        self.secrets_view = QTextEdit()
        self.secrets_view.setReadOnly(True)
        self.secrets_view.setMaximumHeight(160)
        layout.addWidget(self.secrets_view)

    # -- target --------------------------------------------------------------

    def set_target(self, path):
        if path:
            self.target_edit.setText(path)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select app / binary to capture")
        if path:
            self.target_edit.setText(path)

    # -- capture lifecycle ---------------------------------------------------

    def start_capture(self, launch=True):
        if not tc.available():
            self.status.setText("mitmdump not found — pip install mitmproxy")
            return
        if not tc.ca_exists():
            self.status.setText("Generating mitmproxy CA… run once: mitmdump")
            return
        self._reset()
        port = self.port_spin.value()
        self._cap_file = os.path.join(tempfile.gettempdir(),
                                      f"re_capture_{int(time.time())}.jsonl")
        self._proxy_proc = tc.start_proxy(port, self._cap_file)
        if self._proxy_proc is None:
            self.status.setText("Failed to start proxy.")
            return
        self._offset = 0
        self._timer.start(700)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText(f"Proxy on 127.0.0.1:{port} — starting app…")
        if launch:
            target = self.target_edit.text().strip()
            if target:
                base = os.path.basename(target.rstrip("/")).replace(".app", "")
                if tc.app_running(base):
                    self.status.setText(
                        f"⚠ {base} is already running — QUIT it fully first, then click "
                        "Capture again. (Apps hand a second launch to the running copy, "
                        "which isn't proxied.)  Meanwhile, Run Test Request still works.")
                else:
                    QTimer.singleShot(1500, lambda: self._launch(target, port))
            else:
                self.status.setText(f"Proxy on :{port} (no target — use Run Test Request, "
                                    "or set a target and Stop/Start)")

    def _launch(self, target, port):
        self._app_proc = tc.launch_app(target, port)
        if self._app_proc is None:
            self.status.setText(f"Proxy on :{port} — couldn't launch '{os.path.basename(target)}'. "
                                "Try Run Test Request, or a CLI/Electron app.")
        else:
            self.status.setText(f"Capturing {os.path.basename(target)} (proxy :{port})…")

    def run_test_request(self):
        if self._proxy_proc is None:
            self.start_capture(launch=False)
        port = self.port_spin.value()
        QTimer.singleShot(800, lambda: tc.run_test_request(port))
        self.status.setText("Sent a test HTTPS request through the proxy…")

    def stop_capture(self):
        self._timer.stop()
        for proc in (self._app_proc, self._proxy_proc):
            try:
                if proc and proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass
        self._app_proc = None
        self._proxy_proc = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status.setText(f"Stopped — {len(self.flows)} request(s) captured.")

    def _reset(self):
        self.flows = []
        self._all_secrets = []
        self.table.setRowCount(0)
        self.req_view.clear()
        self.resp_view.clear()
        self.flow_secrets.clear()
        self.secrets_view.clear()

    # -- tail + display ------------------------------------------------------

    def _tail(self):
        if not self._cap_file or not os.path.exists(self._cap_file):
            return
        try:
            with open(self._cap_file, "r", encoding="utf-8") as f:
                f.seek(self._offset)
                chunk = f.read()
                self._offset = f.tell()
        except OSError:
            return
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "method" not in rec:
                continue
            self._add_flow(rec)

    def _add_flow(self, rec):
        self.flows.append(rec)
        r = self.table.rowCount()
        self.table.insertRow(r)
        ts = time.strftime("%H:%M:%S", time.localtime(rec.get("ts", time.time())))
        n_keys = len(rec.get("secrets", []))
        cells = [ts, rec.get("method", ""), rec.get("host", ""), rec.get("path", ""),
                 str(rec.get("status", "")), str(n_keys) if n_keys else ""]
        for c, val in enumerate(cells):
            self.table.setItem(r, c, QTableWidgetItem(val))
        # Aggregate secrets.
        for sct in rec.get("secrets", []):
            entry = f"[{sct['type']}]  {sct['value']}\n    from {rec.get('method')} {rec.get('url')}"
            if entry not in self._all_secrets:
                self._all_secrets.append(entry)
        if self._all_secrets:
            self.secrets_view.setPlainText("\n".join(self._all_secrets))
        self.table.scrollToBottom()

    def _show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.flows):
            return
        rec = self.flows[idx]
        req = [f"{rec.get('method')} {rec.get('url')}", ""]
        req += [f"{k}: {v}" for k, v in rec.get("req_headers", {}).items()]
        if rec.get("req_body"):
            req += ["", "--- body ---", self._pretty(rec["req_body"])]
        self.req_view.setPlainText("\n".join(req))

        resp = [f"Status: {rec.get('status')}", ""]
        resp += [f"{k}: {v}" for k, v in rec.get("resp_headers", {}).items()]
        if rec.get("resp_body"):
            resp += ["", "--- body ---", self._pretty(rec["resp_body"])]
        self.resp_view.setPlainText("\n".join(resp))

        secs = rec.get("secrets", [])
        if secs:
            self.flow_secrets.setPlainText(
                "\n".join(f"[{s['type']}]  {s['value']}" for s in secs))
        else:
            self.flow_secrets.setPlainText("No secrets found in this request.")

    @staticmethod
    def _pretty(text):
        try:
            return json.dumps(json.loads(text), indent=2)[:200_000]
        except Exception:
            return text[:200_000]
