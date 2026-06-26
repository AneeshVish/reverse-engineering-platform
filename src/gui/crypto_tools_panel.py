from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QLabel, QHBoxLayout, QLineEdit)
from PyQt6.QtCore import Qt
import subprocess
import sys
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from src.utils.paths import script_path

class CryptoToolsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Encrypted File Scanner
        self.scan_btn = QPushButton("Scan for Encrypted Files")
        self.scan_btn.clicked.connect(self.scan_encrypted_files)
        layout.addWidget(self.scan_btn)

        # Static Crypto Analyzer
        self.analyze_btn = QPushButton("Analyze Crypto Routines in Binary")
        self.analyze_btn.clicked.connect(self.analyze_crypto_routines)
        layout.addWidget(self.analyze_btn)

        # Entropy Plotter
        self.entropy_btn = QPushButton("Plot File Entropy")
        self.entropy_btn.clicked.connect(self.plot_entropy)
        layout.addWidget(self.entropy_btn)

        # Decrypt File
        decrypt_layout = QHBoxLayout()
        self.decrypt_input = QLineEdit()
        self.decrypt_input.setPlaceholderText("Encrypted file path")
        self.decrypt_output = QLineEdit()
        self.decrypt_output.setPlaceholderText("Output file path")
        self.decrypt_key = QLineEdit()
        self.decrypt_key.setPlaceholderText("Key (hex or base64)")
        self.decrypt_algo = QLineEdit()
        self.decrypt_algo.setPlaceholderText("Algo (aes/des)")
        self.decrypt_iv = QLineEdit()
        self.decrypt_iv.setPlaceholderText("IV (optional)")
        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        for w in [self.decrypt_input, self.decrypt_output, self.decrypt_key, self.decrypt_algo, self.decrypt_iv, self.decrypt_btn]:
            decrypt_layout.addWidget(w)
        layout.addLayout(decrypt_layout)

        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        # Entropy plot canvas
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        self.canvas.hide()

    def scan_encrypted_files(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not dir_path:
            return
        cmd = [sys.executable, script_path("scan_encrypted_files"), dir_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)
        self.canvas.hide()

    def analyze_crypto_routines(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Binary to Analyze")
        if not file_path:
            return
        cmd = [sys.executable, script_path("analyze_crypto_routines"), file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)
        self.canvas.hide()

    def plot_entropy(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Plot Entropy")
        if not file_path:
            return
        cmd = [sys.executable, script_path("plot_entropy"), file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        # The plot_entropy script shows a plot itself, but here we plot inline
        # So, we re-implement entropy calculation and plot
        entropies = self.calculate_file_entropy(file_path)
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.plot(entropies)
        ax.set_title(f"Entropy plot: {os.path.basename(file_path)}")
        ax.set_xlabel("Block number")
        ax.set_ylabel("Entropy (bits)")
        self.canvas.draw()
        self.canvas.show()
        self.output.setPlainText(f"Plotted entropy for {file_path}")

    def calculate_file_entropy(self, path, blocksize=4096):
        import math
        entropies = []
        try:
            with open(path, 'rb') as f:
                while True:
                    data = f.read(blocksize)
                    if not data:
                        break
                    freq = [0] * 256
                    for b in data:
                        freq[b] += 1
                    entropy = 0.0
                    for count in freq:
                        if count == 0:
                            continue
                        p = count / len(data)
                        entropy -= p * math.log2(p)
                    entropies.append(entropy)
        except Exception:
            pass
        return entropies

    def decrypt_file(self):
        input_path = self.decrypt_input.text().strip()
        output_path = self.decrypt_output.text().strip()
        key = self.decrypt_key.text().strip()
        algo = self.decrypt_algo.text().strip() or 'aes'
        iv = self.decrypt_iv.text().strip()
        if not input_path or not output_path or not key:
            self.output.setPlainText("Input, output, and key are required.")
            return
        cmd = [sys.executable, script_path("decrypt_file"), input_path, output_path, key, '--algo', algo]
        if iv:
            cmd += ['--iv', iv]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)
        self.canvas.hide()
