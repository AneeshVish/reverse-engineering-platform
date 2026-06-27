"""'Insights' summary shown in the right dock.

Surfaces the key facts about the loaded binary at a glance. Designed to be
responsive: it lives in a scroll area, values wrap instead of clipping, and the
whole panel can shrink to a narrow dock without cutting content off.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QScrollArea,
    QSizePolicy,
)


class InsightsPanel(QWidget):
    reanalyze_requested = pyqtSignal()

    _FIELDS = [
        ("format", "Format"), ("arch", "Arch"), ("size", "Size"),
        ("functions", "Functions"), ("sections", "Sections"),
        ("instructions", "Instr."), ("blocks", "Blocks"),
        ("secrets", "Secrets"), ("endpoints", "Endpoints"),
        ("protection", "Protection"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._values = {}
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        content.setMinimumWidth(150)   # can shrink to a narrow dock
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Insights")
        title.setObjectName("Heading")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("Card")
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(14, 12, 14, 12)
        card_l.setSpacing(8)
        for key, label in self._FIELDS:
            row = QHBoxLayout()
            row.setSpacing(8)
            lab = QLabel(label)
            lab.setObjectName("Dim")
            lab.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
            val = QLabel("—")
            val.setWordWrap(True)   # long values wrap instead of clipping
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            val.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            row.addWidget(lab, 0)
            row.addStretch(1)
            row.addWidget(val, 1)
            card_l.addLayout(row)
            self._values[key] = val
        layout.addWidget(card)

        self.reanalyze_btn = QPushButton("Re-analyze")
        self.reanalyze_btn.setObjectName("Primary")
        self.reanalyze_btn.clicked.connect(self.reanalyze_requested.emit)
        layout.addWidget(self.reanalyze_btn)
        layout.addStretch()

        scroll.setWidget(content)

    def clear(self):
        for v in self._values.values():
            v.setText("—")

    def update_field(self, key, value):
        if key in self._values:
            self._values[key].setText(str(value))

    def update_from(self, **fields):
        for k, v in fields.items():
            self.update_field(k, v)
