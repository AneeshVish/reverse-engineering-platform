# -*- coding: utf-8 -*-
"""Persistent backend status strip (Phase 016 spec, 10.2).

Operational telemetry, not a navigation destination -- a row of small state
dots (one for overall API connectivity, one per backend subsystem), styled
like VSCode's remote-connection indicator or Docker Desktop's engine status.
Clicking a dot opens a small popover with that subsystem's detail text; it
never navigates away from whatever the user is currently looking at.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMenu, QPushButton, QSizePolicy

from src.gui.ui_states import PipelineState, state_object_name

# component key (from GET /health's `components` dict) -> friendly label.
# "Extensions" mirrors the Plugins -> Extensions rename (10.4) for consistency.
_COMPONENT_LABELS: dict[str, str] = {
    "domain-producers.manager": "Producers",
    "static-analysis.manager": "Static Analysis",
    "storage-evidence.manager": "Storage",
    "knowledge-graph.manager": "Graph",
    "reasoning.manager": "Reasoning",
    "investigation.manager": "Investigation",
    "reporting.manager": "Reporting",
    "plugin-sdk.manager": "Extensions",
    "public-api.job-manager": "Jobs",
}

_DOT_ORDER = [
    "domain-producers.manager",
    "static-analysis.manager",
    "storage-evidence.manager",
    "knowledge-graph.manager",
    "reasoning.manager",
    "investigation.manager",
    "reporting.manager",
    "plugin-sdk.manager",
    "public-api.job-manager",
]


class _StatusDot(QLabel):
    clicked = pyqtSignal()

    def __init__(self, label: str, parent=None) -> None:
        super().__init__(f"● {label}", parent)
        self._label = label
        self._detail = ""
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_state(PipelineState.NOT_INITIALIZED, "")

    def set_state(self, state: PipelineState, detail: str) -> None:
        self._detail = detail
        self.setObjectName(state_object_name(state))
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def detail_text(self) -> str:
        return f"{self._label}: {self._detail}" if self._detail else self._label


class StatusStrip(QFrame):
    """The persistent header shown at the top of every Pipeline Workspace page."""

    reconnect_requested = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("StatusStrip")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(14)

        self._api_dot = _StatusDot("API")
        self._api_dot.clicked.connect(lambda: self._show_detail(self._api_dot))
        layout.addWidget(self._api_dot)

        self._dots: dict[str, _StatusDot] = {}
        for key in _DOT_ORDER:
            dot = _StatusDot(_COMPONENT_LABELS[key])
            dot.clicked.connect(lambda _checked=False, d=dot: self._show_detail(d))
            self._dots[key] = dot
            layout.addWidget(dot)

        layout.addStretch(1)

        self._reconnect_btn = QPushButton("Reconnect")
        self._reconnect_btn.setVisible(False)
        self._reconnect_btn.clicked.connect(self.reconnect_requested.emit)
        layout.addWidget(self._reconnect_btn)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def _show_detail(self, dot: _StatusDot) -> None:
        menu = QMenu(self)
        menu.addAction(dot.detail_text())
        menu.exec(dot.mapToGlobal(dot.rect().bottomLeft()))

    def update_from_health(self, api_state: PipelineState, health) -> None:
        """``health`` is a ``reveng_public_api.HealthResponse`` or ``None``."""

        self._api_dot.set_state(api_state, api_state.value)
        self._reconnect_btn.setVisible(api_state == PipelineState.OFFLINE)

        if health is None:
            for dot in self._dots.values():
                dot.set_state(PipelineState.OFFLINE, "unreachable")
            return

        for key, dot in self._dots.items():
            detail = health.components.get(key, "unknown")
            state = PipelineState.CONNECTED if detail == "healthy" else PipelineState.FAILED
            dot.set_state(state, detail)
