"""Virtual disassembly QListView — constant memory for large binaries."""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QListView, QVBoxLayout, QWidget

from src.gui.models.disasm_model import VirtualDisasmModel


class DisasmView(QWidget):
    """Drop-in replacement for QTextEdit disassembly with virtual scrolling."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._model = VirtualDisasmModel(self)
        self._list = QListView(self)
        self._list.setModel(self._model)
        self._list.setUniformItemSizes(True)
        self._list.setWordWrap(False)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        font = QFont("Menlo")
        if not font.exactMatch():
            font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._list.setFont(font)
        layout.addWidget(self._list)

    @property
    def model(self) -> VirtualDisasmModel:
        return self._model

    def setPlainText(self, text: str):
        self._model.set_lines(text.splitlines() if text else [])

    def set_program_model(self, program_model):
        self._model.set_program_model(program_model)

    def toPlainText(self) -> str:
        return self._model.to_plain_text()

    def clear(self):
        self._model.set_lines([])

    def scroll_to_address(self, address: int):
        row = self._model.find_address_row(address)
        if row >= 0:
            idx = self._model.index(row, 0)
            self._list.scrollTo(idx)

    def ensureCursorVisible(self):
        pass
