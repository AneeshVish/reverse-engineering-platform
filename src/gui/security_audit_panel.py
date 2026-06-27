"""Concrete, navigable Security Audit.

Driven by src/core/vuln_audit: every finding has exact coordinates (section +
virtual address + enclosing function) and cross-references to the code that uses
it. Double-click a finding or a cross-reference to jump to that address in the
Disassembly view.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSplitter,
    QTableWidget, QTableWidgetItem, QTextEdit, QListWidget, QListWidgetItem,
    QHeaderView, QAbstractItemView,
)

_SEV_COLOR = {
    "critical": "#f7768e", "high": "#ff9e64", "medium": "#e0af68", "low": "#9ece6a",
}


class SecurityAuditPanel(QWidget):
    # Emitted with a virtual address to navigate to in the Disassembly view.
    navigate_requested = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ctx = None
        self._findings = []
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Concrete Vulnerability Map")
        title.setObjectName("Heading")
        layout.addWidget(title)
        info = QLabel(
            "Every finding is resolved to its exact location (section + address + "
            "function) and cross-referenced to the code that USES it. "
            "Double-click a finding or a cross-reference to jump straight to it.")
        info.setObjectName("Dim")
        info.setWordWrap(True)
        layout.addWidget(info)

        row = QHBoxLayout()
        self.run_btn = QPushButton("Run Security Audit")
        self.run_btn.setObjectName("Primary")
        self.run_btn.clicked.connect(self.run_audit)
        row.addWidget(self.run_btn)
        self.summary = QLabel("Load a binary, then run the audit.")
        self.summary.setObjectName("Dim")
        row.addWidget(self.summary)
        row.addStretch()
        layout.addLayout(row)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Category", "Value", "Location", "Function", "Used by"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.table.itemDoubleClicked.connect(self._jump_to_finding)
        split.addWidget(self.table)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        rl.addWidget(self.detail, 1)
        xlabel = QLabel("Cross-references — double-click to jump to that address")
        xlabel.setObjectName("Dim")
        rl.addWidget(xlabel)
        self.xref_list = QListWidget()
        self.xref_list.itemDoubleClicked.connect(self._jump_to_xref)
        rl.addWidget(self.xref_list, 1)
        split.addWidget(right)
        split.setSizes([720, 520])
        layout.addWidget(split, 1)

    # -- context from the main window ----------------------------------------

    def set_context(self, path, sections, functions, instructions, imports, source_dir=None):
        self._ctx = {
            "path": path, "sections": sections, "functions": functions,
            "instructions": instructions, "imports": imports, "source_dir": source_dir,
        }
        self.summary.setText("Ready — click Run Security Audit.")

    # -- run -----------------------------------------------------------------

    def run_audit(self):
        from src.core import vuln_audit
        if not self._ctx or not self._ctx.get("path"):
            self.summary.setText("Open a binary first.")
            return
        try:
            with open(self._ctx["path"], "rb") as f:
                data = f.read()
        except OSError as e:
            self.summary.setText(f"Could not read binary: {e}")
            return
        self._findings = vuln_audit.audit(
            data, self._ctx["sections"], self._ctx["functions"],
            self._ctx["instructions"], self._ctx["imports"])
        # For Electron apps, also scan the extracted JS source — that's where the
        # real secrets live (the native binary is just a launcher stub).
        src_dir = self._ctx.get("source_dir")
        if src_dir:
            import glob
            import os
            for f in glob.glob(os.path.join(src_dir, "**", "*"), recursive=True):
                if os.path.isfile(f) and f.lower().endswith(
                        (".js", ".mjs", ".cjs", ".json", ".html", ".env", ".cfg", ".config", ".ts")):
                    try:
                        with open(f, "rb") as fh:
                            tb = fh.read(8 * 1024 * 1024)
                    except OSError:
                        continue
                    self._findings.extend(
                        vuln_audit.audit_source_text(os.path.relpath(f, src_dir), tb))
            self._findings.sort(key=lambda fd: fd.sort_key())
        self._populate()

    def _populate(self):
        from collections import Counter
        self.table.setRowCount(0)
        self.detail.clear()
        self.xref_list.clear()
        by_sev = Counter(f.severity for f in self._findings)
        self.summary.setText(
            f"{len(self._findings)} findings — "
            + "  ".join(f"{s}: {by_sev.get(s, 0)}"
                       for s in ("critical", "high", "medium", "low") if by_sev.get(s)))
        for f in self._findings:
            r = self.table.rowCount()
            self.table.insertRow(r)
            loc = f"{f.section} @ 0x{f.vaddr:x}" if f.vaddr else (f.section or "import")
            used = (f"{f.xrefs[0].func}@0x{f.xrefs[0].addr:x}"
                    + (f" +{len(f.xrefs) - 1}" if len(f.xrefs) > 1 else "")) if f.xrefs else ""
            cells = [f.severity.upper(), f.category, f.value, loc,
                     f.function or "", used]
            for c, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if c == 0:
                    item.setForeground(QColor(_SEV_COLOR.get(f.severity, "#c0caf5")))
                self.table.setItem(r, c, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

    def _current(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        i = rows[0].row()
        return self._findings[i] if i < len(self._findings) else None

    def _show_detail(self):
        f = self._current()
        if f is None:
            return
        lines = [f"[{f.severity.upper()}]  {f.category}", "",
                 f"value:    {f.value}",
                 f"location: {f.section} @ 0x{f.vaddr:x}  (file offset {f.file_offset})"
                 if f.vaddr else f"location: {f.section or 'import'}"]
        if f.function:
            lines.append(f"function: {f.function} (0x{f.func_addr:x})")
        lines += ["", f.detail]
        if f.context:
            lines += ["", "context:", f.context]
        self.detail.setPlainText("\n".join(lines))
        self.xref_list.clear()
        for x in f.xrefs:
            it = QListWidgetItem(f"{x.func}  @  0x{x.addr:x}")
            it.setData(Qt.ItemDataRole.UserRole, x.addr)
            self.xref_list.addItem(it)

    def _jump_to_finding(self, _item):
        f = self._current()
        if f is None:
            return
        addr = f.xrefs[0].addr if f.xrefs else f.vaddr
        if addr:
            self.navigate_requested.emit(int(addr))

    def _jump_to_xref(self, item):
        addr = item.data(Qt.ItemDataRole.UserRole)
        if addr:
            self.navigate_requested.emit(int(addr))
