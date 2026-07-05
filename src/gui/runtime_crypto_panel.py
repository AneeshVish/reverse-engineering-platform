"""Runtime Crypto Capture panel — spawn/attach a local process and read its
key/IV/plaintext as it uses cryptography. All hooking lives in core/runtime_crypto.

Frida callbacks fire on Frida's own thread; events reach the UI through a Qt signal
(thread-safe queued delivery). The capture controller is owned by the panel so the
Frida session stays alive after the start worker finishes.
"""

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QWidget,
)

from src.core import resign
from src.core import runtime_crypto as rc


class _StartWorker(QThread):
    ok = pyqtSignal(str)
    fail = pyqtSignal(str)

    def __init__(self, cap, mode, target):
        super().__init__()
        self.cap, self.mode, self.target = cap, mode, target

    def run(self):
        try:
            if self.mode == "spawn":
                pid = self.cap.spawn(self.target)
                self.ok.emit(f"spawned + hooked '{self.target}' (pid {pid})")
            else:
                self.cap.attach(self.target)
                self.ok.emit(f"attached + hooked '{self.target}'")
        except Exception as e:
            self.fail.emit(str(e))


class _ResignWorker(QThread):
    """Copy + re-sign a .app so Frida can attach. codesign/ditto are slow-ish
    and must not run on the UI thread."""
    done = pyqtSignal(dict)

    def __init__(self, app_path):
        super().__init__()
        self.app_path = app_path

    def run(self):
        self.done.emit(resign.prepare_instrumentable_copy(self.app_path))


class RuntimeCryptoPanel(QWidget):
    _event = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("Runtime Crypto Capture")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)

        note = QLabel(
            "Reads key / IV / plaintext AND full HTTPS request/response bodies at the "
            "endpoint by hooking the TARGET's own crypto + TLS calls (CommonCrypto / "
            "OpenSSL / BoringSSL, incl. SSL_write / SSL_read) with Frida. It does not "
            "break AES, reverse SHA, or defeat TLS — it reads what the app itself "
            "encrypts/decrypts. For Electron apps (Claude/Slack), use Spawn & Hook: it "
            "cold-starts the app and follows child processes so the TLS hooks land in "
            "the process that makes the API calls. Use only on software you own or are "
            "authorized to analyze on this machine.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        layout.addWidget(note)

        self._cap = None
        self._worker = None
        self._resign_worker = None
        self._event.connect(self._append_event)

        row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("program path to spawn, or process name/PID to attach")
        self.browse_btn = QPushButton("Browse…")
        self.browse_btn.clicked.connect(self._browse)
        row.addWidget(self.target_edit, 1)
        row.addWidget(self.browse_btn)
        layout.addLayout(row)

        # Hardened macOS apps (Electron: Claude/Slack/…) refuse a debugger/Frida
        # attach unless they carry get-task-allow. This prepares an instrumentable
        # COPY (original untouched) and points the target at it. Frida stays a
        # separate runtime source; this is just its prerequisite on macOS.
        prep_row = QHBoxLayout()
        self.resign_btn = QPushButton("Prepare macOS .app for instrumentation (re-sign a copy)")
        self.resign_btn.clicked.connect(self._prepare_app)
        prep_row.addWidget(self.resign_btn)
        prep_row.addStretch()
        layout.addLayout(prep_row)
        if not resign.available():
            self.resign_btn.setEnabled(False)
            self.resign_btn.setToolTip("Needs macOS with codesign/ditto (Xcode Command Line Tools).")

        btn_row = QHBoxLayout()
        self.spawn_btn = QPushButton("Spawn & Hook")
        self.spawn_btn.setObjectName("Primary")
        self.spawn_btn.clicked.connect(lambda: self._start("spawn"))
        self.attach_btn = QPushButton("Attach by Name/PID")
        self.attach_btn.clicked.connect(lambda: self._start("attach"))
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.spawn_btn)
        btn_row.addWidget(self.attach_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        if not rc.available():
            self._set_unavailable()

    def _set_unavailable(self):
        for b in (self.spawn_btn, self.attach_btn):
            b.setEnabled(False)
        self.output.setPlainText(
            "Frida is not installed, so live capture is unavailable.\n"
            "Install it to enable this feature:\n\n    pip install frida\n\n"
            "(The rest of the application works without it.)")

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a program to spawn")
        if path:
            self.target_edit.setText(path)

    def _prepare_app(self):
        app_path, _ = QFileDialog.getOpenFileName(
            self, "Select a macOS .app to make instrumentable", "/Applications",
            "Applications (*.app);;All files (*)")
        if not app_path:
            return
        if not resign.is_app_bundle(app_path):
            self.output.append(f"[ERROR] Not a .app bundle: {app_path}")
            return
        self.resign_btn.setEnabled(False)
        self.output.append(
            f"\nPreparing an instrumentable copy of {app_path} …\n"
            "(copying the bundle and re-signing it with get-task-allow — this can "
            "take a few seconds for large apps)")
        self._resign_worker = _ResignWorker(app_path)
        self._resign_worker.done.connect(self._on_resigned)
        self._resign_worker.start()

    def _on_resigned(self, res):
        self.resign_btn.setEnabled(resign.available())
        if res.get("ok"):
            self.output.append(f"[OK] {res['message']}")
            # Point the target at the instrumentable copy's executable (spawn), or
            # the copy bundle if the exe couldn't be resolved.
            self.target_edit.setText(res.get("exe_path") or res.get("copy_path") or "")
        else:
            self.output.append(f"[ERROR] {res.get('message', 'unknown error')}")

    def _start(self, mode):
        target = self.target_edit.text().strip()
        if not target:
            self.output.setPlainText("Enter a program path (spawn) or process name/PID (attach).")
            return
        if mode == "attach":
            try:
                target = int(target)
            except ValueError:
                pass
        self._cap = rc.RuntimeCryptoCapture(on_event=self._event.emit)
        self.output.setPlainText("Starting capture…\n")
        self.spawn_btn.setEnabled(False)
        self.attach_btn.setEnabled(False)
        self._worker = _StartWorker(self._cap, mode, target)
        self._worker.ok.connect(self._on_started)
        self._worker.fail.connect(self._on_failed)
        self._worker.start()

    def _on_started(self, msg):
        self.stop_btn.setEnabled(True)
        self.output.append(f"[OK] {msg}\nWaiting for crypto calls… (exercise the target now)\n")

    def _on_failed(self, err):
        self.spawn_btn.setEnabled(rc.available())
        self.attach_btn.setEnabled(rc.available())
        self.output.append(f"[ERROR] {err}")

    def _append_event(self, evt):
        self.output.append(rc.format_event(evt) + "\n")
        try:
            from src.core.adapters.frida_adapter import frida_event_to_plaintext
            from src.core.plaintext_bus import get_bus
            pe = frida_event_to_plaintext(evt)
            if pe:
                get_bus().ingest(pe)
        except Exception:
            pass

    def _stop(self):
        if self._cap is not None:
            self._cap.stop()
        self.stop_btn.setEnabled(False)
        self.spawn_btn.setEnabled(rc.available())
        self.attach_btn.setEnabled(rc.available())
        self.output.append("\n[stopped]")
