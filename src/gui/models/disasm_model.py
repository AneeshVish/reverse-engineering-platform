"""Virtual O(1) disassembly list model backed by ProgramModel or line list."""

from PyQt6.QtCore import QAbstractListModel, QModelIndex, Qt


class VirtualDisasmModel(QAbstractListModel):
    """QAbstractListModel for millions of disassembly lines with uniform row height."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lines = []

    def set_lines(self, lines):
        self.beginResetModel()
        self._lines = list(lines)
        self.endResetModel()

    def set_program_model(self, model):
        if model is None or not getattr(model, "instructions", None):
            self.set_lines([])
            return
        self.set_lines(model.disassembly_lines())

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self._lines)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._lines):
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._lines[index.row()]
        return None

    def line_at(self, row: int) -> str:
        if 0 <= row < len(self._lines):
            return self._lines[row]
        return ""

    def to_plain_text(self) -> str:
        return "\n".join(self._lines)

    def find_address_row(self, address: int) -> int:
        needle = f"{address:08x}:"
        for i, line in enumerate(self._lines):
            if line.startswith(needle):
                return i
        return -1
