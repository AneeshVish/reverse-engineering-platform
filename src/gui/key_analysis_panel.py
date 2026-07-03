from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QLabel, QHBoxLayout, QLineEdit)
from PyQt6.QtCore import Qt
import subprocess
import sys
import os

from src.utils.paths import script_path

class KeyAnalysisPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._target_path = ""
        self.init_ui()

    def set_target(self, path: str):
        self._target_path = path or ""
        if path and hasattr(self, 'output'):
            self.output.append(f"[Target] {path}")

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Find Key Strings
        self.keystr_btn = QPushButton("Find Key Strings in Files/Dirs")
        self.keystr_btn.clicked.connect(self.find_key_strings)
        layout.addWidget(self.keystr_btn)

        # Dump Memory Keys
        self.memkey_btn = QPushButton("Extract Keys from Memory Dump")
        self.memkey_btn.clicked.connect(self.dump_memory_keys)
        layout.addWidget(self.memkey_btn)

        # Dictionary Attack
        dict_layout = QHBoxLayout()
        self.dict_input = QLineEdit()
        self.dict_input.setPlaceholderText("Encrypted file path")
        self.dict_wordlist = QLineEdit()
        self.dict_wordlist.setPlaceholderText("Wordlist file path")
        self.dict_algo = QLineEdit()
        self.dict_algo.setPlaceholderText("Algo (aes/des)")
        self.dict_iv = QLineEdit()
        self.dict_iv.setPlaceholderText("IV (optional)")
        self.dict_btn = QPushButton("Run Dictionary Attack")
        self.dict_btn.clicked.connect(self.dictionary_attack)
        for w in [self.dict_input, self.dict_wordlist, self.dict_algo, self.dict_iv, self.dict_btn]:
            dict_layout.addWidget(w)
        layout.addLayout(dict_layout)

        # Brute Force Attack
        brute_layout = QHBoxLayout()
        self.brute_input = QLineEdit()
        self.brute_input.setPlaceholderText("Encrypted file path")
        self.brute_algo = QLineEdit()
        self.brute_algo.setPlaceholderText("Algo (aes/des)")
        self.brute_keylen = QLineEdit()
        self.brute_keylen.setPlaceholderText("Key length (e.g., 4)")
        self.brute_charset = QLineEdit()
        self.brute_charset.setPlaceholderText("Charset (e.g., 0123456789abcdef)")
        self.brute_iv = QLineEdit()
        self.brute_iv.setPlaceholderText("IV (optional)")
        self.brute_max = QLineEdit()
        self.brute_max.setPlaceholderText("Max attempts (default 1000000)")
        self.brute_btn = QPushButton("Run Brute Force Attack")
        self.brute_btn.clicked.connect(self.brute_force_attack)
        for w in [self.brute_input, self.brute_algo, self.brute_keylen, self.brute_charset, self.brute_iv, self.brute_max, self.brute_btn]:
            brute_layout.addWidget(w)
        layout.addLayout(brute_layout)

        # Output area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

    def find_key_strings(self):
        target, _ = QFileDialog.getOpenFileName(self, "Select File or Directory to Scan")
        if not target:
            return
        cmd = [sys.executable, script_path("find_key_strings"), target]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)

    def dump_memory_keys(self):
        dump_path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump File")
        if not dump_path:
            return
        cmd = [sys.executable, script_path("dump_memory_keys"), dump_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)

    def dictionary_attack(self):
        input_path = self.dict_input.text().strip()
        wordlist_path = self.dict_wordlist.text().strip()
        algo = self.dict_algo.text().strip() or 'aes'
        iv = self.dict_iv.text().strip()
        if not input_path or not wordlist_path:
            self.output.setPlainText("Encrypted file and wordlist are required.")
            return
        cmd = [sys.executable, script_path("dictionary_attack"), input_path, wordlist_path, '--algo', algo]
        if iv:
            cmd += ['--iv', iv]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)

    def brute_force_attack(self):
        input_path = self.brute_input.text().strip()
        algo = self.brute_algo.text().strip() or 'aes'
        keylen = self.brute_keylen.text().strip()
        charset = self.brute_charset.text().strip() or '0123456789abcdef'
        iv = self.brute_iv.text().strip()
        max_attempts = self.brute_max.text().strip()
        if not input_path or not keylen:
            self.output.setPlainText("Encrypted file and key length are required.")
            return
        cmd = [sys.executable, script_path("brute_force_attack"), input_path, '--algo', algo, '--keylen', keylen, '--charset', charset]
        if iv:
            cmd += ['--iv', iv]
        if max_attempts:
            cmd += ['--max', max_attempts]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.output.setPlainText(proc.stdout + proc.stderr)
