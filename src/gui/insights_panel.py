"""Compact 'Insights' summary shown in the right dock.

Surfaces the key facts about the loaded binary at a glance: format, architecture,
size, function/section counts, secrets, endpoints, and protection level.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QLabel, QPushButton, QFrame, QSizePolicy,
)


class InsightsPanel(QWidget):
    reanalyze_requested = pyqtSignal()

    _FIELDS = [
        ("format", "Format"), ("arch", "Architecture"), ("size", "Size"),
        ("functions", "Functions"), ("sections", "Sections"),
        ("instructions", "Instructions"), ("blocks", "Basic blocks"),
        ("secrets", "Secrets"), ("endpoints", "Endpoints"),
        ("protection", "Protection"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._values = {}
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Insights")
        title.setObjectName("Heading")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("Card")
        grid = QGridLayout(card)
        grid.setContentsMargins(14, 14, 14, 14)
        grid.setVerticalSpacing(9)
        grid.setHorizontalSpacing(10)
        for row, (key, label) in enumerate(self._FIELDS):
            lab = QLabel(label)
            lab.setObjectName("Dim")
            val = QLabel("—")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            grid.addWidget(lab, row, 0)
            grid.addWidget(val, row, 1)
            self._values[key] = val
        layout.addWidget(card)

        self.reanalyze_btn = QPushButton("Re-analyze")
        self.reanalyze_btn.setObjectName("Primary")
        self.reanalyze_btn.clicked.connect(self.reanalyze_requested.emit)
        layout.addWidget(self.reanalyze_btn)

        layout.addStretch()

    def clear(self):
        for v in self._values.values():
            v.setText("—")

    def update_field(self, key, value):
        if key in self._values:
            self._values[key].setText(str(value))

    def update_from(self, **fields):
        for k, v in fields.items():
            self.update_field(k, v)
