"""A VS Code-style command palette (Ctrl+K): fuzzy-filter and run results
from a ``SearchProviderRegistry`` (functions, commands, reports, extensions,
and -- in later phases -- whatever else registers a provider)."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QListWidget, QListWidgetItem,
)


class CommandPalette(QDialog):
    def __init__(self, registry_or_actions, parent=None):
        """``registry_or_actions``: a ``SearchProviderRegistry`` (preferred),
        or (for backward compatibility) a flat list of ``(label, callback)``
        tuples, wrapped in a single-provider registry automatically."""

        super().__init__(parent)
        self._registry = self._coerce_registry(registry_or_actions)
        self.setWindowFlags(Qt.WindowType.Popup)
        self.setObjectName("Card")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Type to search…  (Enter to run, Esc to close)")
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
    def _coerce_registry(registry_or_actions):
        from src.gui.search_providers import CommandProvider, SearchProviderRegistry

        if isinstance(registry_or_actions, SearchProviderRegistry):
            return registry_or_actions
        registry = SearchProviderRegistry()
        registry.register(CommandProvider(list(registry_or_actions)))
        return registry

    def _refilter(self, text):
        self.list.clear()
        for result in self._registry.search(text):
            label = f"[{result.result_type}] {result.display_text}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, result.callback)
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
