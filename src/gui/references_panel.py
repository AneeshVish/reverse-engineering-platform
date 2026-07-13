# -*- coding: utf-8 -*-
"""References & Relationships (Phase 016 spec, 10.9).

A collapsible sub-panel inside the Disassembly tab, generalizing
``vuln_audit.py``'s existing xref-index technique to any address (not just
audit findings). Phase 018 naturally extends this same panel with backend
graph relationships once the Graph route exists -- no rename, no restructure.
"""

from __future__ import annotations

import re

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QLabel, QListWidget, QListWidgetItem, QPushButton, QVBoxLayout, QWidget

from src.core.vuln_audit import _FunctionIndex, _build_xref_index

_CALL_MNEMONICS = {"call", "bl", "blr"}
_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")


class ReferencesPanel(QWidget):
    """Referenced By / Calls / Uses for a given address, computed from the
    current analysis' instructions -- collapsible, off by default."""

    navigate_requested = pyqtSignal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._instructions: list[dict] = []
        self._functions: list[dict] = []
        self._fnindex: _FunctionIndex | None = None
        self._xref_index: dict[int, list] = {}
        self._expanded = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)

        self._toggle_btn = QPushButton("▸ References & Relationships")
        self._toggle_btn.setFlat(True)
        self._toggle_btn.clicked.connect(self._on_toggle)
        layout.addWidget(self._toggle_btn)

        self._body = QWidget()
        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(12, 4, 0, 0)

        body_layout.addWidget(QLabel("Referenced By", objectName="Dim"))
        self._referenced_by = QListWidget()
        self._referenced_by.itemDoubleClicked.connect(self._on_item_activated)
        body_layout.addWidget(self._referenced_by)

        body_layout.addWidget(QLabel("Calls", objectName="Dim"))
        self._calls = QListWidget()
        self._calls.itemDoubleClicked.connect(self._on_item_activated)
        body_layout.addWidget(self._calls)

        body_layout.addWidget(QLabel("Uses", objectName="Dim"))
        self._uses = QListWidget()
        self._uses.itemDoubleClicked.connect(self._on_item_activated)
        body_layout.addWidget(self._uses)

        self._body.setVisible(False)
        layout.addWidget(self._body)

    def _on_toggle(self) -> None:
        self._expanded = not self._expanded
        self._body.setVisible(self._expanded)
        self._toggle_btn.setText(
            ("▾" if self._expanded else "▸") + " References & Relationships"
        )

    def set_analysis(self, instructions: list[dict], functions: list[dict]) -> None:
        self._instructions = instructions or []
        self._functions = functions or []
        self._fnindex = _FunctionIndex(self._functions)
        self._xref_index = _build_xref_index(self._instructions, self._fnindex)

    def show_address(self, address: int) -> None:
        self._referenced_by.clear()
        self._calls.clear()
        self._uses.clear()
        if self._fnindex is None:
            return

        for xref in self._xref_index.get(address, []):
            item = QListWidgetItem(f"{xref.func} @ 0x{xref.addr:x}")
            item.setData(1000, xref.addr)
            self._referenced_by.addItem(item)

        func_name, func_addr = self._fnindex.at(address)
        func_end = self._next_function_addr(func_addr)

        seen_calls: set[int] = set()
        seen_uses: set[int] = set()
        for ins in self._instructions:
            addr = ins.get("address", 0)
            if not (func_addr <= addr < func_end):
                continue
            mnemonic = (ins.get("mnemonic") or "").lower()
            op = ins.get("op_str") or ""
            match = _HEX_RE.search(op)
            if not match:
                continue
            target = int(match.group(1), 16)
            if mnemonic in _CALL_MNEMONICS:
                if target not in seen_calls:
                    seen_calls.add(target)
                    tname, _ = self._fnindex.at(target)
                    item = QListWidgetItem(f"{tname or hex(target)}  @ 0x{target:x}")
                    item.setData(1000, target)
                    self._calls.addItem(item)
            elif target != address and target not in seen_uses:
                seen_uses.add(target)
                item = QListWidgetItem(f"0x{target:x}")
                item.setData(1000, target)
                self._uses.addItem(item)

    def _next_function_addr(self, func_addr: int) -> int:
        addrs = sorted(int(f.get("address", 0)) for f in self._functions)
        for a in addrs:
            if a > func_addr:
                return a
        return func_addr + 0x100000  # generous tail bound for the last function

    def _on_item_activated(self, item: QListWidgetItem) -> None:
        addr = item.data(1000)
        if addr is not None:
            self.navigate_requested.emit(addr)
