from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, QHBoxLayout
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import subprocess
import os
import sys

class MitmproxyCaptureThread(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, log_path, parent=None):
        super().__init__(parent)
        self.log_path = log_path
        self.proc = None

    def run(self):
        # Start mitmproxy in regular mode, saving flows to log_path
        try:
            self.proc = subprocess.Popen([
                'mitmproxy', '-w', self.log_path
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
            for line in self.proc.stdout:
                self.output_signal.emit(line)
        except Exception as e:
            self.output_signal.emit(f"[ERROR] mitmproxy failed: {e}")

    def stop(self):
        if self.proc:
            self.proc.terminate()

class NetworkCapturePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.capture_thread = None
        self.log_path = os.path.join(os.getcwd(), 'mitmproxy_capture.log')

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.info_label = QLabel("""
<b>Network Traffic Capture</b><br>
1. Click 'Start Capture' to launch mitmproxy.<br>
2. Set your application's/system's proxy to <b>127.0.0.1:8080</b>.<br>
3. Interact with the target app to generate API traffic.<br>
4. Click 'Stop Capture' and then 'Analyze Log' to extract tokens and API calls.<br>
""")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.analyze_btn = QPushButton("Analyze Log")
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.analyze_btn)
        layout.addLayout(btn_layout)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.analyze_btn.clicked.connect(self.analyze_log)

    def start_capture(self):
        self.log_output.append("[INFO] Starting mitmproxy...")
        self.capture_thread = MitmproxyCaptureThread(self.log_path)
        self.capture_thread.output_signal.connect(self.log_output.append)
        self.capture_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.quit()
            self.capture_thread.wait()
            self.capture_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log_output.append("[INFO] mitmproxy stopped.")

    def analyze_log(self):
        if not os.path.exists(self.log_path):
            self.log_output.append("[ERROR] No mitmproxy log found.")
            return
        self.log_output.append("[INFO] Analyzing mitmproxy log for tokens and API calls...")
        try:
            with open(self.log_path, 'rb') as f:
                data = f.read().decode(errors='replace')
            import re
            # Extract all HTTP requests and responses
            requests = re.findall(r"(GET|POST|PUT|DELETE|PATCH) (.*?) HTTP/1.[01]\\r\\n([\\s\\S]*?)\\r\\n\\r\\n", data)
            tokens = re.findall(r"([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+)", data)  # JWT
            tokens += re.findall(r"Bearer ([A-Za-z0-9\\-\\._~\\+/]+=*)", data)
            tokens += re.findall(r"access[_-]?token[=: ]+([A-Za-z0-9\\-_=\\.]{16,})", data, re.I)
            # Display API calls
            self.log_output.append("\n===== API Calls =====")
            for method, url, headers in requests:
                self.log_output.append(f"{method} {url}\nHeaders: {headers}\n")
            # Display tokens
            self.log_output.append("\n===== Tokens =====")
            for t in set(tokens):
                self.log_output.append(t)
        except Exception as e:
            self.log_output.append(f"[ERROR] Failed to analyze log: {e}")
