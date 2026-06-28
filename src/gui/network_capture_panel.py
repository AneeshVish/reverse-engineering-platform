"""Network Traffic Capture — decrypted, app-targeted HTTPS interception.

Not a packet sniffer. Point it at an app and it launches that app through a local
mitmproxy with the CA trusted via env vars, then shows — in real time — every API
call: method + URL, request/response headers and bodies, secrets, the PII fields
being sent, a tracker tag, and a one-click ownership PROOF for the server.

Designed to be one-click: `auto_start(app)` starts everything (no ports, no manual
proxy control). The only friction we can't remove is that a single-instance app
already running must be relaunched to be captured — that stays one explicit click.
"""

import json
import os
import tempfile
import time

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)

from src.core import pii_classify, tracker_list, traffic_capture as tc
from src.gui.icons import icon as qicon


class _ProofWorker(QThread):
    """Off-thread ownership proof (TLS handshake + WHOIS are network calls)."""
    done = pyqtSignal(str, str)   # host, formatted proof

    def __init__(self, host):
        super().__init__()
        self.host = host

    def run(self):
        try:
            from src.core import tls_identity
            text = tls_identity.format_proof(tls_identity.ownership_proof(self.host))
        except Exception as e:
            text = f"Proof unavailable for {self.host}: {e}"
        self.done.emit(self.host, text)


class NetworkCapturePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.flows = []
        self._proxy_proc = None
        self._app_proc = None
        self._cap_file = None
        self._offset = 0
        self._port = tc.DEFAULT_PORT
        self._all_secrets = []
        self._target = ""
        self._system_service = None   # set while system-wide capture is active
        self._static_hosts = []
        self._proof_cache = {}
        self._proof_worker = None
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
            "Launches the target app through a local HTTPS interceptor and shows its real "
            "API calls, headers, bodies, secrets, the PII it sends, and proof of who owns "
            "each server — decrypted, in real time. No setup needed.")
        info.setObjectName("Dim")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Target row (no port control — the port is fixed and hidden).
        row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Target app / binary (auto-filled from the loaded file)")
        row.addWidget(self.target_edit, 1)
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        layout.addLayout(row)

        # System-wide mode: capture EVERY app via the system proxy + trusted CA
        # (how Charles/Proxyman work). Catches already-running apps; needs admin once.
        self.system_cb = QCheckBox(
            "Capture ALL apps system-wide (admin once; reverts on Stop; "
            "pinned apps still won't decrypt)")
        layout.addWidget(self.system_cb)

        # One adaptive primary action + small Stop + secondary test.
        row2 = QHBoxLayout()
        self.start_btn = QPushButton("  Start Capture")
        self.start_btn.setObjectName("Primary")
        self.start_btn.setIcon(qicon("fa5s.play"))
        self.start_btn.clicked.connect(self._on_primary)
        self.stop_btn = QPushButton("  Stop")
        self.stop_btn.setIcon(qicon("fa5s.stop"))
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.test_btn = QPushButton("  Test")
        self.test_btn.setIcon(qicon("fa5s.vial"))
        self.test_btn.setToolTip("Fire one sample HTTPS request through the proxy to prove capture works.")
        self.test_btn.clicked.connect(self.run_test_request)
        row2.addWidget(self.start_btn)
        row2.addWidget(self.stop_btn)
        row2.addWidget(self.test_btn)
        row2.addStretch()
        self.status = QLabel("Idle")
        self.status.setObjectName("Dim")
        row2.addWidget(self.status)
        layout.addLayout(row2)

        # Calls table (left) | detail tabs (right).
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Method", "Host", "Path", "Status", "Flags", "Keys"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        split.addWidget(self.table)

        self.detail = QTabWidget()
        self.req_view = QTextEdit(); self.req_view.setReadOnly(True)
        self.resp_view = QTextEdit(); self.resp_view.setReadOnly(True)
        self.pii_view = QTextEdit(); self.pii_view.setReadOnly(True)
        self.proof_view = QTextEdit(); self.proof_view.setReadOnly(True)
        self.flow_secrets = QTextEdit(); self.flow_secrets.setReadOnly(True)
        self.correlation_view = QTextEdit(); self.correlation_view.setReadOnly(True)
        self.detail.addTab(self.req_view, "Request")
        self.detail.addTab(self.resp_view, "Response")
        self.detail.addTab(self.pii_view, "User Data")
        self.detail.addTab(self.proof_view, "Server Proof")
        self.detail.addTab(self.flow_secrets, "Secrets")
        self.detail.addTab(self.correlation_view, "Static↔Live")
        split.addWidget(self.detail)
        split.setSizes([640, 640])
        layout.addWidget(split, 1)

        sec_label = QLabel("All Captured API Keys / Tokens / Secrets")
        sec_label.setObjectName("Heading")
        layout.addWidget(sec_label)
        self.secrets_view = QTextEdit()
        self.secrets_view.setReadOnly(True)
        self.secrets_view.setMaximumHeight(150)
        layout.addWidget(self.secrets_view)

    # -- target / auto-start -------------------------------------------------

    def set_target(self, path):
        """Set (but don't launch) — used when a binary is loaded for analysis."""
        if path:
            self._target = path
            self.target_edit.setText(path)
            self._refresh_primary()

    def set_static_hosts(self, hosts):
        """Endpoints found by static analysis — for static↔live correlation proof."""
        self._static_hosts = list(hosts or [])
        self._update_correlation()

    def _update_correlation(self):
        from src.core import endpoint_correlation as ec
        live_hosts = [f.get("host", "") for f in self.flows if f.get("host")]
        rows = ec.correlate(self._static_hosts, live_hosts)
        self.correlation_view.setPlainText(ec.format_correlation(rows))

    def auto_start(self, path=None):
        """One-click entry: arm on `path` and begin capturing immediately."""
        if path:
            self.set_target(path)
        # System-wide capture changes system settings + asks for admin — never do
        # that automatically; require an explicit Start click.
        if self.system_cb.isChecked():
            self.status.setText("System-wide mode selected — click Start Capture to "
                                "enable it (asks for admin once).")
            return
        if not self._preflight():
            return
        base = self._target_base()
        if base and tc.app_running(base):
            # Don't silently kill a running app; make relaunch one explicit click.
            self._refresh_primary(relaunch=True)
            self.status.setText(f"{base} is already running — click “Recapture” to relaunch it "
                                "through the interceptor (the only way to capture it).")
            return
        self._begin(launch=True)

    def _refresh_primary(self, relaunch=False):
        base = self._target_base() or "App"
        if relaunch:
            self.start_btn.setText(f"  Recapture {base} (relaunches)")
            self.start_btn.setIcon(qicon("fa5s.redo"))
        else:
            self.start_btn.setText(f"  Start Capture" + (f" — {base}" if base != "App" else ""))
            self.start_btn.setIcon(qicon("fa5s.play"))

    def _on_primary(self):
        if not self._preflight():
            return
        if self.system_cb.isChecked():
            self._begin(launch=False)   # system-wide: no per-app launch
            return
        base = self._target_base()
        if base and tc.app_running(base):
            self.status.setText(f"Quitting {base} and relaunching through the interceptor…")
            tc.quit_app(base)
            QTimer.singleShot(1200, lambda: self._begin(launch=True))
        else:
            self._begin(launch=True)

    def _target_base(self):
        t = (self.target_edit.text() or self._target).strip()
        return os.path.basename(t.rstrip("/")).replace(".app", "") if t else ""

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select app / binary to capture")
        if path:
            self._target = path
            self.target_edit.setText(path)
            self._refresh_primary()

    # -- capture lifecycle ---------------------------------------------------

    def _preflight(self):
        if not tc.available():
            self.status.setText("mitmproxy not installed — run: pip install mitmproxy")
            return False
        if not tc.ca_exists():
            self.status.setText("First-run CA setup needed — run `mitmdump` once, then retry.")
            return False
        return True

    def _begin(self, launch=True):
        self._reset()
        self._port = tc.pick_port()
        self._cap_file = os.path.join(tempfile.gettempdir(),
                                      f"re_capture_{int(time.time())}.jsonl")
        self._proxy_proc = tc.start_proxy(self._port, self._cap_file)
        if self._proxy_proc is None:
            self.status.setText("Failed to start the interceptor.")
            return
        self._offset = 0
        self._timer.start(700)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        # System-wide mode: trust CA + set system proxy (one admin prompt). Captures
        # every non-pinned app, including ones already running — no relaunch.
        if self.system_cb.isChecked():
            self.status.setText("Requesting admin to enable system-wide capture…")
            ok, service, out = tc.enable_system_capture(self._port)
            if not ok:
                self.status.setText("System-wide capture not enabled "
                                    f"(admin declined / failed). {out[:120]}")
                self.stop_capture()
                return
            self._system_service = service
            self.status.setText(f"Capturing ALL apps on {service} (proxy hidden). "
                                "Use any app to generate traffic.")
            return

        if launch and (self.target_edit.text().strip() or self._target):
            target = self.target_edit.text().strip() or self._target
            self.status.setText("Launching app through the interceptor…")
            QTimer.singleShot(1400, lambda: self._launch(target))
        else:
            self.status.setText("Interceptor running — use Test, or set a target.")

    def _launch(self, target):
        self._app_proc = tc.launch_app(target, self._port)
        base = os.path.basename(target.rstrip("/"))
        if self._app_proc is None:
            self.status.setText(f"Couldn't launch '{base}'. Use Test, or pick an app/CLI binary.")
        else:
            self.status.setText(f"Capturing {base}…  (use the app to generate traffic)")

    def run_test_request(self):
        if self._proxy_proc is None:
            if not self._preflight():
                return
            self._begin(launch=False)
        QTimer.singleShot(800, lambda: tc.run_test_request(self._port))
        self.status.setText("Sent a test HTTPS request through the interceptor…")

    def stop_capture(self):
        self._timer.stop()
        # Revert the system proxy first so networking is always restored.
        if self._system_service:
            try:
                tc.disable_system_capture(self._system_service)
            except Exception:
                pass
            self._system_service = None
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
        self._refresh_primary()
        self.status.setText(f"Stopped — {len(self.flows)} call(s) captured.")

    def _reset(self):
        self.flows = []
        self._all_secrets = []
        self.table.setRowCount(0)
        for v in (self.req_view, self.resp_view, self.pii_view, self.proof_view,
                  self.flow_secrets, self.correlation_view, self.secrets_view):
            v.clear()

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
            if "method" in rec:
                self._add_flow(rec)

    def _add_flow(self, rec):
        self.flows.append(rec)
        host = rec.get("host", "")
        tracker = tracker_list.classify(host)
        pii_hits = pii_classify.find_pii(rec.get("req_body", "") or "")
        rec["_tracker"] = tracker
        rec["_pii"] = pii_hits

        flags = []
        if tracker:
            flags.append("TRACKER")
        if pii_hits:
            flags.append(f"PII:{len(pii_hits)}")
        n_keys = len(rec.get("secrets", []))

        r = self.table.rowCount()
        self.table.insertRow(r)
        ts = time.strftime("%H:%M:%S", time.localtime(rec.get("ts", time.time())))
        cells = [ts, rec.get("method", ""), host, rec.get("path", ""),
                 str(rec.get("status", "")), " ".join(flags), str(n_keys) if n_keys else ""]
        for c, val in enumerate(cells):
            item = QTableWidgetItem(val)
            if c == 5 and flags:
                item.setForeground(Qt.GlobalColor.red if tracker else Qt.GlobalColor.darkYellow)
            self.table.setItem(r, c, item)

        for sct in rec.get("secrets", []):
            entry = f"[{sct['type']}]  {sct['value']}\n    from {rec.get('method')} {rec.get('url')}"
            if entry not in self._all_secrets:
                self._all_secrets.append(entry)
        if self._all_secrets:
            self.secrets_view.setPlainText("\n".join(self._all_secrets))
        self.table.scrollToBottom()
        if self._static_hosts:
            self._update_correlation()

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
            req += ["", "--- body (the message sent) ---", self._pretty(rec["req_body"])]
        self.req_view.setPlainText("\n".join(req))

        resp = [f"Status: {rec.get('status')}", ""]
        resp += [f"{k}: {v}" for k, v in rec.get("resp_headers", {}).items()]
        if rec.get("resp_body"):
            resp += ["", "--- body ---", self._pretty(rec["resp_body"])]
        self.resp_view.setPlainText("\n".join(resp))

        # User Data (PII) tab.
        pii_hits = rec.get("_pii") or pii_classify.find_pii(rec.get("req_body", "") or "")
        if pii_hits:
            lines = ["Personal/identifying fields in this request's payload:", ""]
            for label, sev, sample in pii_hits:
                lines.append(f"  [{sev.upper()}] {label}: {sample}")
            tracker = rec.get("_tracker")
            if tracker:
                lines += ["", f"⚠ Sent to a known {tracker} endpoint ({rec.get('host')}) — "
                          "this is concrete evidence of tracking."]
            self.pii_view.setPlainText("\n".join(lines))
        else:
            self.pii_view.setPlainText("No personal/identifying data detected in this payload.")

        # Server Proof tab (async TLS/WHOIS).
        host = rec.get("host", "")
        if host in self._proof_cache:
            self.proof_view.setPlainText(self._proof_cache[host])
        elif host:
            self.proof_view.setPlainText(f"Fetching ownership proof for {host}…")
            self._proof_worker = _ProofWorker(host)
            self._proof_worker.done.connect(self._on_proof)
            self._proof_worker.start()

        secs = rec.get("secrets", [])
        self.flow_secrets.setPlainText(
            "\n".join(f"[{s['type']}]  {s['value']}" for s in secs)
            if secs else "No secrets found in this request.")

    def _on_proof(self, host, text):
        self._proof_cache[host] = text
        rows = self.table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self.flows):
            if self.flows[rows[0].row()].get("host") == host:
                self.proof_view.setPlainText(text)

    @staticmethod
    def _pretty(text):
        try:
            return json.dumps(json.loads(text), indent=2)[:200_000]
        except Exception:
            return str(text)[:200_000]
