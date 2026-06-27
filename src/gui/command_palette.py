"""A VS Code-style command palette (⌘K): fuzzy-filter and run registered actions."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QListWidget, QListWidgetItem,
)


class CommandPalette(QDialog):
    def __init__(self, actions, parent=None):
        """actions: list of (label, callback)."""
        super().__init__(parent)
        self._actions = list(actions)
        self.setWindowFlags(Qt.WindowType.Popup)
        self.setObjectName("Card")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Type a command…  (Enter to run, Esc to close)")
        self.search.textChanged.connect(self._refilter)
        self.search.returnPressed.connect(self._run_current)
        layout.addWidget(self.search)

        self.list = QListWidget()
        self.list.itemActivated.connect(lambda _it: self._run_current())
        self.list.itemClicked.connect(lambda _it: self._run_current())
        layout.addWidget(self.list)

        self._refilter("")
        self.search.setFocus()

    @staticmethod
    def _matches(query, label):
        """Subsequence fuzzy match (chars of query appear in order in label)."""
        if not query:
            return True
        q = query.lower()
        it = iter(label.lower())
        return all(ch in it for ch in q)

    def _refilter(self, text):
        self.list.clear()
        for label, cb in self._actions:
            if self._matches(text, label):
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, cb)
                self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _run_current(self):
        item = self.list.currentItem()
        if item is None and self.list.count():
            item = self.list.item(0)
        if item is None:
            return
        cb = item.data(Qt.ItemDataRole.UserRole)
        self.accept()
        if callable(cb):
            cb()

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key.Key_Down:
            self.list.setCurrentRow(min(self.list.currentRow() + 1, self.list.count() - 1))
        elif key == Qt.Key.Key_Up:
            self.list.setCurrentRow(max(self.list.currentRow() - 1, 0))
        elif key == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)
