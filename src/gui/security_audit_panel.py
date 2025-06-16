from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog)
from PyQt6.QtCore import Qt
import subprocess
import sys
import os

class SecurityAuditPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.last_findings = None

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.audit_btn = QPushButton("Run Security Audit (Find Weaknesses)")
        self.audit_btn.clicked.connect(self.run_audit)
        layout.addWidget(self.audit_btn)

        self.patch_btn = QPushButton("Show Patch Recommendations (Requires User Consent)")
        self.patch_btn.clicked.connect(self.show_patch_recommendations)
        self.patch_btn.setEnabled(False)
        layout.addWidget(self.patch_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        self.findings_output = QTextEdit()
        self.findings_output.setReadOnly(True)
        layout.addWidget(self.findings_output)

    def run_audit(self):
        target, _ = QFileDialog.getOpenFileName(self, "Select File or Directory to Audit")
        if not target:
            return
        cmd = [sys.executable, os.path.join("scripts", "security_audit.py"), target]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        self.last_findings = proc.stdout
        self.patch_btn.setEnabled(True)
        # Display grouped findings immediately after audit
        patch_sections = {
            'Master Key': [],
            'Hardcoded Secret': [],
            'Weak Algorithm': [],
            'Insecure API Usage': [],
            'Short Key': [],
            'Suspicious Key Material': [],
            'Token': []
        }
        for line in proc.stdout.splitlines():
            if 'master_key' in line:
                patch_sections['Master Key'].append(line)
            if 'hardcoded_secret' in line:
                patch_sections['Hardcoded Secret'].append(line)
            if 'weak_algo' in line:
                patch_sections['Weak Algorithm'].append(line)
            if 'insecure_api' in line:
                patch_sections['Insecure API Usage'].append(line)
            if 'short_key' in line:
                patch_sections['Short Key'].append(line)
            if 'long_key' in line or 'high_entropy_key' in line:
                patch_sections['Suspicious Key Material'].append(line)
            if 'token' in line:
                patch_sections['Token'].append(line)
        findings_output = "\nFindings (by Type):\n"
        for section, findings in patch_sections.items():
            if findings:
                findings_output += f"\n===== {section} =====\n" + "\n".join(findings) + "\n"
        if findings_output.strip() == "Findings (by Type):":
            self.findings_output.setPlainText("\nNo findings detected.")
        else:
            self.findings_output.setPlainText(findings_output)

    def show_patch_recommendations(self):
        if not self.last_findings:
            self.output.setPlainText("Run an audit first.")
            return
        # Only show recommendations after explicit user action
        patch_sections = {
            'Hardcoded Secret': [],
            'Weak Algorithm': [],
            'Insecure API Usage': [],
            'Short Key': [],
            'Suspicious Key Material': [],
            'Token': []
        }
        for line in self.last_findings.splitlines():
            if 'hardcoded_secret' in line:
                patch_sections['Hardcoded Secret'].append(line)
            if 'weak_algo' in line:
                patch_sections['Weak Algorithm'].append(line)
            if 'insecure_api' in line:
                patch_sections['Insecure API Usage'].append(line)
            if 'short_key' in line:
                patch_sections['Short Key'].append(line)
            if 'long_key' in line or 'high_entropy_key' in line:
                patch_sections['Suspicious Key Material'].append(line)
            if 'token' in line:
                patch_sections['Token'].append(line)
        findings_output = "\nFindings (by Type):\n"
        for section, findings in patch_sections.items():
            if findings:
                findings_output += f"\n===== {section} =====\n" + "\n".join(findings) + "\n"
        if findings_output.strip() == "Findings (by Type):":
            self.findings_output.setPlainText("\nNo findings detected.")
        else:
            self.findings_output.setPlainText(findings_output)
        # Patch recommendations as before
        patch_steps = {
            'Hardcoded Secret': """
Step 1: Locate the hardcoded secret/key in your source or binary (see finding for exact value and location).
Step 2: Remove the secret from code. Replace it with a reference to a secure config file, environment variable, or secure vault (e.g., os.environ['SECRET_KEY']).
Step 3: If using a config file, ensure it is not committed to version control and has restricted permissions.
Step 4: Update all code that references the old secret to use the new secure method.
Step 5: Rotate the secret (generate a new one) if it may have been exposed.
Step 6: Rebuild and redeploy the application.
""",
            'Weak Algorithm': """
Step 1: Identify where the weak algorithm (e.g., DES, RC4, MD5, SHA1, ECB) is used in the code.
Step 2: Replace it with a strong algorithm (e.g., AES, GCM, SHA256+).
Step 3: Update any key sizes, IV handling, or output formats as required by the stronger algorithm.
Step 4: Test the new implementation for compatibility and correctness.
Step 5: Remove any legacy/deprecated code.
""",
            'Insecure API Usage': """
Step 1: Find the code using insecure APIs (e.g., ECB mode, static IVs).
Step 2: Switch to secure modes (CBC, GCM) and ensure IVs are random and unique per encryption.
Step 3: Refactor the code to use secure cryptographic libraries and best practices.
Step 4: Add unit tests to verify encryption/decryption security.
""",
            'Short Key': """
Step 1: Locate all cryptographic keys shorter than recommended (e.g., <128 bits for AES).
Step 2: Generate new, sufficiently long keys (AES: 128/192/256 bits).
Step 3: Replace all instances of the short key in code, configs, and deployments.
Step 4: Rotate/expire any data encrypted with the old key if possible.
Step 5: Document the new key management policy.
""",
            'Suspicious Key Material': """
Step 1: Review the flagged high-entropy or long key material for legitimacy (could be a real key or random data).
Step 2: If it is a real key, ensure it is securely stored (not hardcoded or exposed in the binary).
Step 3: Move the key to a secure storage solution (environment variable, vault, encrypted config).
Step 4: Remove any plaintext or exposed copies from the code/binary.
Step 5: Rotate the key if it may have been leaked.
""",
            'Token': """
Step 1: Locate the token (JWT, OAuth, API, session, etc.) in the code, config, or memory.
Step 2: Remove any hardcoded or static tokens from code and configs.
Step 3: Ensure tokens are generated dynamically and securely at runtime.
Step 4: Use secure storage and transmission (HTTPS, encrypted storage).
Step 5: Rotate/expire tokens if they may have been leaked.
"""
        }
        patch_output = "\nPatch Recommendations (by Type):\n"
        for section, findings in patch_sections.items():
            if findings:
                patch_output += f"\n===== {section} =====\n" + patch_steps[section] + "\n"
        if patch_output.strip() == "Patch Recommendations (by Type):":
            self.output.append("\nNo patch recommendations found or no issues detected.")
        else:
            self.output.append(patch_output)
