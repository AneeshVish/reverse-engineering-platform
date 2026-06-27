from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QCheckBox
from PyQt6.QtCore import pyqtSignal

class PseudocodeToggleWidget(QWidget):
    """
    A small widget with a label and a toggle (checkbox) to switch between offline and AI pseudocode generation.
    Emits 'toggle_changed' signal with a boolean: True for AI, False for offline.
    """
    toggle_changed = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        self.label = QLabel("AI Pseudocode:")
        self.toggle = QCheckBox()
        self.toggle.setChecked(False)
        self.toggle.setToolTip("Enable to use AI-generated pseudocode. Disable for offline pseudocode.")
        layout.addWidget(self.label)
        layout.addWidget(self.toggle)
        layout.addStretch()
        self.toggle.stateChanged.connect(self._emit_state)

    def _emit_state(self, state):
        self.toggle_changed.emit(self.toggle.isChecked())
