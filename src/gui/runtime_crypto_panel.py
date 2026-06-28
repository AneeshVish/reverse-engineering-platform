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


class RuntimeCryptoPanel(QWidget):
    _event = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("Runtime Crypto Capture")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)

        note = QLabel(
            "Reads key / IV / plaintext at the endpoint by hooking the TARGET's own "
            "crypto calls (CommonCrypto / OpenSSL / BoringSSL) with Frida. It does not "
            "break AES or reverse SHA — it reads what the app itself decrypts. Use only "
            "on a process you spawn, own, or are authorized to analyze on this machine.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        layout.addWidget(note)

        self._cap = None
        self._worker = None
        self._event.connect(self._append_event)

        row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("program path to spawn, or process name/PID to attach")
        self.browse_btn = QPushButton("Browse…")
        self.browse_btn.clicked.connect(self._browse)
        row.addWidget(self.target_edit, 1)
        row.addWidget(self.browse_btn)
        layout.addLayout(row)

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

    def _stop(self):
        if self._cap is not None:
            self._cap.stop()
        self.stop_btn.setEnabled(False)
        self.spawn_btn.setEnabled(rc.available())
        self.attach_btn.setEnabled(rc.available())
        self.output.append("\n[stopped]")
