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
from src.core.adapters.mitm_adapter import flow_to_plaintext_events
from src.core.plaintext_bus import get_bus, subscribe
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


class ServerEvidenceView(QWidget):
    """Prove a discovered server is REAL by showing the actual user traffic to it.

    A bare host/IP proves nothing — anyone can resolve a name or ping a box. What
    proves the server is genuinely used by the app is the concrete request/response
    traffic observed from THIS machine: the methods, paths, bodies, and secrets the
    user's own actions generated. This view groups live flows by server and, for a
    selected server, lays out that evidence next to the ownership proof.
    """
    proofRequested = pyqtSignal(str)   # host -> ask the panel to fetch TLS/WHOIS proof

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows = []
        self._proof_cache = {}
        self._static_hosts = set()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        hint = QLabel(
            "Each server below is proven by the real requests captured to it — not a "
            "guess or a ping. Select a server to see the traffic that confirms it.")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Server", "Calls", "Methods", "Confirmed"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.table)

        self.evidence = QTextEdit()
        self.evidence.setReadOnly(True)
        self.evidence.setPlaceholderText(
            "Select a server to see the live traffic that proves it's real.")
        split.addWidget(self.evidence)
        split.setSizes([420, 860])
        layout.addWidget(split, 1)

    def _selected_host(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return ""
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def _select_host(self, host):
        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == host:
                self.table.selectRow(r)
                return

    def _on_select(self):
        host = self._selected_host()
        if host:
            self._render_evidence(host)
            self.proofRequested.emit(host)

    def render(self, flows, proof_cache, static_hosts):
        """Rebuild the server list from the current flows, preserving selection."""
        self._flows = flows or []
        self._proof_cache = proof_cache if proof_cache is not None else {}
        self._static_hosts = set(static_hosts or [])

        by_host = {}
        for f in self._flows:
            h = f.get("host", "")
            if h:
                by_host.setdefault(h, []).append(f)

        prev = self._selected_host()
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        # Servers with the most captured calls first — strongest evidence on top.
        for host in sorted(by_host, key=lambda h: (-len(by_host[h]), h)):
            fl = by_host[host]
            methods = ", ".join(sorted({x.get("method", "") for x in fl if x.get("method")}))
            confirmed = "static + live ✓" if host in self._static_hosts else "live"
            r = self.table.rowCount()
            self.table.insertRow(r)
            name = QTableWidgetItem(host)
            name.setData(Qt.ItemDataRole.UserRole, host)
            if host in self._static_hosts:
                name.setForeground(Qt.GlobalColor.green)
            self.table.setItem(r, 0, name)
            self.table.setItem(r, 1, QTableWidgetItem(str(len(fl))))
            self.table.setItem(r, 2, QTableWidgetItem(methods))
            self.table.setItem(r, 3, QTableWidgetItem(confirmed))
        self.table.blockSignals(False)

        if prev and prev in by_host:
            self._select_host(prev)
        elif self.table.rowCount() and not self._selected_host():
            self.table.selectRow(0)
        else:
            cur = self._selected_host()
            if cur:
                self._render_evidence(cur)

    def update_proof(self, host, text):
        """Called when async ownership proof lands; refresh if it's on screen."""
        if self._selected_host() == host:
            self._render_evidence(host)

    def clear(self):
        self._flows = []
        self.table.setRowCount(0)
        self.evidence.clear()

    def _render_evidence(self, host):
        from src.core import server_proof
        flows = [f for f in self._flows if f.get("host") == host]
        self.evidence.setPlainText(server_proof.format_server_proof(
            host, flows,
            ownership_proof=self._proof_cache.get(host),
            static_confirmed=host in self._static_hosts))


class BehaviorInferenceView(QWidget):
    """Evidence-graded inference of server-side behavior from the captured flows.

    Renders src.core.behavior_infer's honesty-first report: every claim carries a
    confidence tier, its evidence, confounders, and how to confirm/falsify — plus
    an explicit list of what CANNOT be proven from client traffic.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        hint = QLabel(
            "Server-side behavior (databases, internal services, LLM backends) cannot be "
            "PROVEN from client traffic. These are graded hypotheses with evidence and "
            "confounders — never present them to a client as facts.")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText(
            "Capture traffic — inferred server-side behavior appears here.")
        layout.addWidget(self.report, 1)

    def render(self, flows):
        from src.core import behavior_infer
        self.report.setPlainText(behavior_infer.format_report(flows or []))

    def clear(self):
        self.report.clear()


class _ReportSubTab(QWidget):
    """Generic read-only report sub-tab."""
    def __init__(self, hint_text="", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if hint_text:
            hint = QLabel(hint_text)
            hint.setObjectName("Dim")
            hint.setWordWrap(True)
            layout.addWidget(hint)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        layout.addWidget(self.report, 1)

    def set_text(self, text):
        self.report.setPlainText(text)

    def clear(self):
        self.report.clear()


class NetworkCapturePanel(QWidget):
    flowsUpdated = pyqtSignal()

    # Hard cap on flows kept in memory.
    MAX_FLOWS = 500
    MAX_SECRETS = 500

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
        self._proof_workers = []
        self._intel = None
        self._plaintext_events = []
        self._ebpf_sniffer = None
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

        self.kernel_cb = QCheckBox(
            "Kernel TLS capture (Linux root + BCC — complements proxy for pinned native apps)")
        layout.addWidget(self.kernel_cb)
        try:
            from src.core import capabilities
            if not capabilities.probe_ebpf_support():
                self.kernel_cb.setEnabled(False)
                self.kernel_cb.setToolTip(
                    "Kernel TLS capture unavailable — Linux root + bcc required "
                    "(see requirements-optional-linux.txt)")
        except Exception:
            self.kernel_cb.setEnabled(False)

        subscribe(self._on_plaintext_bus)

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
        self.clear_btn = QPushButton("  Clear")
        self.clear_btn.setIcon(qicon("fa5s.trash"))
        self.clear_btn.setToolTip("Drop all captured data from memory right now "
                                  "(frees RAM; capture keeps running if active).")
        self.clear_btn.clicked.connect(self.clear_captures)
        row2.addWidget(self.start_btn)
        row2.addWidget(self.stop_btn)
        row2.addWidget(self.test_btn)
        row2.addWidget(self.clear_btn)
        row2.addStretch()
        self.status = QLabel("Idle")
        self.status.setObjectName("Dim")
        row2.addWidget(self.status)
        layout.addLayout(row2)

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

        tls_label = QLabel("Unified TLS Plane (Frida / eBPF plaintext)")
        tls_label.setObjectName("Heading")
        layout.addWidget(tls_label)
        self.tls_plane_view = QTextEdit()
        self.tls_plane_view.setReadOnly(True)
        self.tls_plane_view.setMaximumHeight(120)
        self.tls_plane_view.setPlaceholderText(
            "TLS plaintext from Frida or eBPF appears here (mitmproxy flows in the table above).")
        layout.addWidget(self.tls_plane_view)

    def _on_plaintext_bus(self, event):
        """Receive PlaintextEvents from any plane (Frida, eBPF — mitm ingested in _add_flow)."""
        if event.source_plane == "mitmproxy":
            return
        self._ingest_plaintext_ui(event)

    def _ingest_plaintext_ui(self, event):
        self._plaintext_events.append(event)
        if len(self._plaintext_events) > 200:
            self._plaintext_events.pop(0)
        preview = event.raw_payload[:200].decode("utf-8", errors="replace").replace("\n", " ")
        line = (f"[{event.source_plane}] pid={event.pid} {event.payload_type} "
                f"{event.target_host}:{event.target_port} — {preview}")
        self.tls_plane_view.append(line)
        self.tls_plane_view.verticalScrollBar().setValue(
            self.tls_plane_view.verticalScrollBar().maximum())

    def set_intelligence_panel(self, panel):
        """Attach the Network Intelligence tab so analytics refresh with capture."""
        self._intel = panel
        panel.proofRequested.connect(self._ensure_proof)

    @property
    def server_evidence(self):
        return self._intel.server_evidence if self._intel else None

    @property
    def behavior_view(self):
        return self._intel.behavior_view if self._intel else None

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
        if self._intel:
            self._intel.schedule_refresh(self.flows, self._proof_cache, self._static_hosts)

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
            # Single-instance apps hand a relaunch off to the running instance and
            # exit, so a fixed-delay relaunch captures nothing. Quit, then POLL until
            # the process is really gone before cold-starting under the interceptor.
            self.status.setText(f"Quitting {base} completely (waiting for it to exit)…")
            tc.quit_app(base)
            self._quit_wait_tries = 0
            self._quit_timer = QTimer(self)
            self._quit_timer.timeout.connect(lambda: self._await_exit_then_begin(base))
            self._quit_timer.start(400)
        else:
            self._begin(launch=True)

    def _await_exit_then_begin(self, base):
        """Poll (off the paint path) until `base` has fully exited, then cold-start."""
        self._quit_wait_tries = getattr(self, "_quit_wait_tries", 0) + 1
        if not tc.app_running(base):
            self._quit_timer.stop()
            self.status.setText(f"{base} exited — cold-starting it through the interceptor…")
            self._begin(launch=True)
        elif self._quit_wait_tries >= 20:   # ~8s
            self._quit_timer.stop()
            tc.quit_app(base)   # one more, harder nudge
            self.status.setText(
                f"{base} is still running after quit — it may be single-instance or "
                "protected. Trying anyway; if the table stays empty, quit it manually "
                "and click Start again, or use system-wide capture.")
            self._begin(launch=True)

    @staticmethod
    def _likely_pinned(base):
        """Known apps whose core API traffic is certificate-pinned (won't decrypt via proxy)."""
        b = (base or "").lower()
        return any(p in b for p in (
            "claude", "spotify", "whatsapp", "signal", "telegram", "dropbox",
            "1password", "slack"))

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
        # Remove any previous session's on-disk buffer before starting a new one.
        self._delete_cap_file()
        self._port = tc.pick_port()
        self._cap_file = os.path.join(tempfile.gettempdir(),
                                      f"re_capture_{int(time.time())}.jsonl")
        self._proxy_proc = tc.start_proxy(self._port, self._cap_file)
        if self._proxy_proc is None:
            self.status.setText("Failed to start the interceptor.")
            return
        if self.kernel_cb.isChecked():
            self._start_ebpf()
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
            if not tc.ca_trusted():
                # Proxy is set, but the CA isn't trusted -> clients show "not secure"
                # and capture nothing. Tell the user exactly how to fix it.
                self.status.setText("⚠ Capturing, but the CA is NOT trusted yet — apps will "
                                    "show 'not secure' and won't decrypt. See the fix below.")
                self.output_hint(
                    "The interception CA isn't trusted by macOS, so HTTPS shows 'not secure' "
                    "and nothing decrypts. Trust it once with:\n\n"
                    "  sudo security add-trusted-cert -d -r trustRoot \\\n"
                    "    -k /Library/Keychains/System.keychain "
                    "~/.mitmproxy/mitmproxy-ca-cert.pem\n\n"
                    "Then fully restart the target app and capture again.")
            else:
                self.status.setText(f"Capturing ALL apps on {service} (proxy hidden, CA "
                                    "trusted). Use any app to generate traffic.")
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
        elif tc.is_electron_app(target):
            # Electron: we now inject Chromium proxy + cert switches, so the
            # network service (chat/renderer traffic, not just Node/undici) is
            # routed through us and the interception CA is accepted. This defeats
            # verifier-level pinning; only app-level pinning in JS/native resists.
            self.status.setText(
                f"Capturing {base} (Electron) — routing Chromium's network service "
                "through the interceptor. Use the app (send a chat) to generate traffic.")
            self.output_hint(
                f"{base} is an Electron app. Its chat/API traffic runs through Chromium's "
                "network service, which ignores the HTTP_PROXY env var — so it's launched "
                "with Chromium switches (--proxy-server + --ignore-certificate-errors) to "
                "force it through this interceptor and accept our CA.\n\n"
                "You should now see the real chat requests/responses appear as you use the "
                "app. If the table stays empty for the core API, the app pins at the "
                "application layer (in JS/native, above TLS) — that case is covered by the "
                "Runtime Crypto tab (in-process hooks).")
        else:
            self.status.setText(f"Capturing {base}…  (use the app to generate traffic)")

    def run_test_request(self):
        if self._proxy_proc is None:
            if not self._preflight():
                return
            self._begin(launch=False)
        QTimer.singleShot(800, lambda: tc.run_test_request(self._port))
        self.status.setText("Sent a test HTTPS request through the interceptor…")

    def _start_ebpf(self):
        try:
            from src.core.ebpf_capture.sniffer import eBPFSniffer
            from src.core.adapters.ebpf_adapter import ebpf_event_to_plaintext

            def _on_ebpf(rec):
                pe = ebpf_event_to_plaintext(rec)
                if pe:
                    get_bus().ingest(pe)

            self._ebpf_sniffer = eBPFSniffer(on_event=_on_ebpf)
            if not self._ebpf_sniffer.start():
                self.output_hint(
                    "Kernel TLS capture could not start — need Linux, root, and bcc.")
        except Exception as e:
            self.output_hint(f"Kernel TLS capture error: {e}")

    def stop_capture(self):
        self._timer.stop()
        if self._ebpf_sniffer is not None:
            try:
                self._ebpf_sniffer.stop()
            except Exception:
                pass
            self._ebpf_sniffer = None
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
        # Wait out any in-flight ownership-proof threads so Qt doesn't abort on exit.
        for w in list(self._proof_workers):
            try:
                if w.isRunning():
                    w.wait(2000)
            except Exception:
                pass
        self._proof_workers = []
        # Delete the on-disk capture buffer so nothing is persisted locally.
        self._delete_cap_file()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._refresh_primary()
        self.status.setText(f"Stopped — {len(self.flows)} call(s) captured "
                            "(on-disk buffer deleted).")

    def output_hint(self, text):
        """Surface a help/diagnostic message in the detail pane."""
        self.req_view.setPlainText(text)
        self.detail.setCurrentWidget(self.req_view)

    def _enforce_flow_cap(self):
        """Keep only the newest MAX_FLOWS flows in memory + table (ring buffer)."""
        over = len(self.flows) - self.MAX_FLOWS
        while over > 0 and self.flows:
            self.flows.pop(0)
            self.table.removeRow(0)
            over -= 1

    def _delete_cap_file(self):
        """Remove the transient JSONL capture file (IPC buffer) from disk."""
        f = self._cap_file
        if f and os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    def clear_captures(self):
        """Purge all captured data from memory immediately (frees RAM).

        Works whether or not capture is active. If a capture is running we skip
        past whatever is already on disk (advance the read offset to EOF) so the
        cleared calls don't reappear on the next tail; capture then continues.
        """
        self._reset()
        if self._cap_file and os.path.exists(self._cap_file):
            try:
                self._offset = os.path.getsize(self._cap_file)
            except OSError:
                self._offset = 0
        capturing = self._proxy_proc is not None
        self.status.setText("Cleared captured data from memory." +
                            ("  Still capturing…" if capturing else ""))

    def _reset(self):
        self.flows = []
        self._all_secrets = []
        self.table.setRowCount(0)
        for v in (self.req_view, self.resp_view, self.pii_view, self.proof_view,
                  self.flow_secrets, self.correlation_view, self.secrets_view):
            v.clear()
        if self._intel:
            self._intel.clear()

    def add_region_sample(self, sample: dict):
        if self._intel:
            self._intel.add_region_sample(sample)

    def add_probe_result(self, result: dict):
        if self._intel:
            self._intel.add_probe_result(result)

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
        rec = dict(rec)
        try:
            from src.core import streaming_capture
            rec = streaming_capture.enrich_flow(rec)
        except Exception:
            pass
        for pe in flow_to_plaintext_events(rec):
            get_bus().ingest(pe)
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
        # Are we "following the tail"? True if nothing is selected yet, or the
        # current selection is the row that was last (so a live viewer keeps
        # seeing the newest call). If the user is inspecting an earlier row, we
        # leave their selection alone.
        sel = self.table.selectionModel().selectedRows()
        following = (not sel) or (sel[0].row() == r - 1)

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
        if len(self._all_secrets) > self.MAX_SECRETS:
            del self._all_secrets[:-self.MAX_SECRETS]
        if self._all_secrets:
            self.secrets_view.setPlainText("\n".join(self._all_secrets))

        # Bound memory: keep only the newest MAX_FLOWS calls, dropping the oldest
        # rows in lockstep so self.flows[idx] stays aligned with table row idx.
        self._enforce_flow_cap()

        # Auto-select the newest row so the Request/Response/Secrets/Proof tabs fill
        # immediately — otherwise the detail pane stays blank until a manual click
        # and the capture looks empty even though it worked.
        if following and self.table.rowCount():
            self.table.selectRow(self.table.rowCount() - 1)
        self.table.scrollToBottom()
        if self._static_hosts:
            self._update_correlation()
        if self._intel:
            self._intel.schedule_refresh(self.flows, self._proof_cache, self._static_hosts)
        self.flowsUpdated.emit()

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
            self._ensure_proof(host)

        secs = rec.get("secrets", [])
        self.flow_secrets.setPlainText(
            "\n".join(f"[{s['type']}]  {s['value']}" for s in secs)
            if secs else "No secrets found in this request.")

    def _ensure_proof(self, host):
        """Fetch ownership proof for `host` once (async), shared by the detail tab
        and the Server Evidence view. No-op if already cached or in flight."""
        if not host:
            return
        if host in self._proof_cache:
            if self._intel:
                self._intel.update_proof(host, self._proof_cache[host])
            return
        # Don't start a second worker for a host already being fetched.
        if any(getattr(w, "host", None) == host and w.isRunning()
               for w in self._proof_workers):
            return
        worker = _ProofWorker(host)
        worker.done.connect(self._on_proof)
        # Keep a reference so the QThread isn't garbage-collected mid-run (which
        # aborts Qt with "QThread: Destroyed while thread is still running").
        self._proof_workers.append(worker)
        worker.finished.connect(
            lambda w=worker: self._proof_workers.remove(w)
            if w in self._proof_workers else None)
        worker.start()

    def _on_proof(self, host, text):
        self._proof_cache[host] = text
        rows = self.table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self.flows):
            if self.flows[rows[0].row()].get("host") == host:
                self.proof_view.setPlainText(text)
        if self._intel:
            self._intel.update_proof(host, text)

    @staticmethod
    def _pretty(text):
        try:
            return json.dumps(json.loads(text), indent=2)[:200_000]
        except Exception:
            return str(text)[:200_000]
