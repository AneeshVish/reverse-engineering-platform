# -*- coding: utf-8 -*-
"""Pipeline Workspace -- the RevEng backend's outward-facing surface.

A permanent, extensible shell (Phase 016 spec, 10.1): a persistent
``StatusStrip`` header plus an internal navigation container holding
Pipeline Home / Report / Extensions. Phase 017 only adds destinations here
-- nothing about this container restructures when that lands (10.17).

Navigation ownership (10.1): this widget owns navigation *within* the
Pipeline Workspace; it never reaches out to decide whether the workspace
itself is the active one -- that is ``MainWindow``'s activity rail's job.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.gui.backend_service_controller import BackendServiceController
from src.gui.icons import icon as qicon
from src.gui.status_strip import StatusStrip
from src.gui.ui_states import PipelineState, state_label, state_object_name

logger = logging.getLogger(__name__)


class _StateLabel(QLabel):
    def set_state(self, state: PipelineState) -> None:
        self.setText(state_label(state))
        self.setObjectName(state_object_name(state))
        self.style().unpolish(self)
        self.style().polish(self)


class PipelineHomeView(QWidget):
    """The entry point (10.3): Recent Jobs, Latest Report, Generate Report."""

    generate_requested = pyqtSignal()
    open_report_requested = pyqtSignal(str)  # job_id

    def __init__(self, controller: BackendServiceController, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller

        layout = QVBoxLayout(self)
        heading = QLabel("Pipeline Home")
        heading.setObjectName("Heading")
        layout.addWidget(heading)

        self._state_label = _StateLabel("")
        self._state_label.set_state(PipelineState.NOT_INITIALIZED)
        layout.addWidget(self._state_label)

        generate_btn = QPushButton("  Generate Report")
        generate_btn.setObjectName("Primary")
        generate_btn.setIcon(qicon("fa5s.play"))
        generate_btn.clicked.connect(self.generate_requested.emit)
        layout.addWidget(generate_btn)

        layout.addWidget(QLabel("Recent Jobs", objectName="Dim"))
        self._jobs_list = QListWidget()
        self._jobs_list.itemDoubleClicked.connect(self._on_job_double_clicked)
        layout.addWidget(self._jobs_list)

        self._latest_btn = QPushButton("Open Latest Report")
        self._latest_btn.setEnabled(False)
        self._latest_btn.clicked.connect(self._on_open_latest)
        layout.addWidget(self._latest_btn)

        controller.job_submitted.connect(lambda _job_id: self.refresh())
        controller.job_status_changed.connect(lambda _job_id, _status: self.refresh())
        controller.job_report_ready.connect(lambda _job_id, _content: self.refresh())

    def refresh(self) -> None:
        self._jobs_list.clear()
        for record in self._controller.recent_jobs:
            item = QListWidgetItem(f"{record.job_id}  —  {record.state}")
            item.setData(1000, record.job_id)
            self._jobs_list.addItem(item)
        self._latest_btn.setEnabled(self._controller.latest_report is not None)

    def set_state(self, state: PipelineState) -> None:
        self._state_label.set_state(state)

    def _on_job_double_clicked(self, item: QListWidgetItem) -> None:
        job_id = item.data(1000)
        if job_id:
            self.open_report_requested.emit(job_id)

    def _on_open_latest(self) -> None:
        job_id = self._controller.latest_job_id
        if job_id:
            self.open_report_requested.emit(job_id)


class ReportView(QWidget):
    """A single job's report: submit/poll/report (10.3)."""

    generate_requested = pyqtSignal()

    def __init__(self, controller: BackendServiceController, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller
        self._current_job_id: Optional[str] = None

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        heading = QLabel("Report")
        heading.setObjectName("Heading")
        header.addWidget(heading)
        self._state_label = _StateLabel("")
        self._state_label.set_state(PipelineState.NOT_INITIALIZED)
        header.addWidget(self._state_label)
        header.addStretch(1)
        generate_btn = QPushButton("  Generate Report")
        generate_btn.setObjectName("Primary")
        generate_btn.setIcon(qicon("fa5s.play"))
        generate_btn.clicked.connect(self.generate_requested.emit)
        header.addWidget(generate_btn)
        layout.addLayout(header)

        self._body = QTextEdit()
        self._body.setReadOnly(True)
        self._body.setPlaceholderText("No report yet — click Generate Report.")
        layout.addWidget(self._body)

        controller.job_submitted.connect(self._on_job_submitted)
        controller.job_status_changed.connect(self._on_job_status)
        controller.job_report_ready.connect(self._on_report_ready)
        controller.job_failed.connect(self._on_job_failed)

    def set_state(self, state: PipelineState) -> None:
        self._state_label.set_state(state)

    def show_job(self, job_id: str) -> None:
        self._current_job_id = job_id
        cached = self._controller.cached_report(job_id)
        if cached is not None:
            self._body.setPlainText(cached)
            self.set_state(PipelineState.COMPLETED)
        else:
            self._body.setPlainText("")
            self.set_state(PipelineState.GENERATING)

    def _on_job_submitted(self, job_id: str) -> None:
        self._current_job_id = job_id
        self._body.setPlainText("")
        self.set_state(PipelineState.GENERATING)

    def _on_job_status(self, job_id: str, status) -> None:
        if job_id != self._current_job_id:
            return
        if status.state == "offline":
            self.set_state(PipelineState.OFFLINE)

    def _on_report_ready(self, job_id: str, content: str) -> None:
        if job_id != self._current_job_id:
            return
        self._body.setPlainText(content)
        self.set_state(PipelineState.COMPLETED)

    def _on_job_failed(self, job_id: str, error: str) -> None:
        if job_id != self._current_job_id:
            return
        self._body.setPlainText(f"[ERROR] {error}")
        self.set_state(PipelineState.FAILED)


class ExtensionsView(QWidget):
    """Read-only capability list (10.4) -- 'Extensions', backed by GET /plugins."""

    def __init__(self, controller: BackendServiceController, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller

        layout = QVBoxLayout(self)
        heading = QLabel("Extensions")
        heading.setObjectName("Heading")
        layout.addWidget(heading)
        layout.addWidget(
            QLabel(
                "Any capability discoverable through the backend — "
                "implementation origin is intentionally not distinguished.",
                objectName="Dim",
            )
        )

        self._list = QListWidget()
        layout.addWidget(self._list)

        controller.plugins_ready.connect(self._on_plugins)

    def refresh(self) -> None:
        self._controller.refresh_plugins()

    def _on_plugins(self, plugins) -> None:
        self._list.clear()
        for plugin in plugins:
            caps = ", ".join(plugin.capabilities) if plugin.capabilities else "—"
            self._list.addItem(f"{plugin.name}  ({caps})")


class PipelineWorkspace(QWidget):
    """The full shell: StatusStrip header + Home/Report/Extensions navigation."""

    def __init__(
        self,
        controller: BackendServiceController,
        get_current_binary: Callable[[], Optional[tuple[bytes, str]]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
        self._get_current_binary = get_current_binary

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._status_strip = StatusStrip()
        layout.addWidget(self._status_strip)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._home = PipelineHomeView(controller)
        self._report = ReportView(controller)
        self._extensions = ExtensionsView(controller)
        self._tabs.addTab(self._home, "Pipeline Home")
        self._tabs.addTab(self._report, "Report")
        self._tabs.addTab(self._extensions, "Extensions")
        layout.addWidget(self._tabs)

        controller.health_changed.connect(self._status_strip.update_from_health)
        self._status_strip.reconnect_requested.connect(controller.reconnect_now)

        self._home.generate_requested.connect(self._on_generate_requested)
        self._home.open_report_requested.connect(self._on_open_report)
        self._report.generate_requested.connect(self._on_generate_requested)

        controller.initialized.connect(self._on_initialized)

    def _on_initialized(self) -> None:
        self._extensions.refresh()
        self._home.refresh()

    def _on_generate_requested(self) -> None:
        data = self._get_current_binary()
        if data is None:
            logger.info("[Pipeline] Generate Report requested with no binary loaded")
            self._report.set_state(PipelineState.NOT_INITIALIZED)
            return
        content, source_ref = data
        self._controller.generate_report(content, source_ref=source_ref)
        self._tabs.setCurrentWidget(self._report)

    def _on_open_report(self, job_id: str) -> None:
        self._report.show_job(job_id)
        self._tabs.setCurrentWidget(self._report)

    # -- navigation-ownership rule (10.1): internal-only selection ------------

    def select_destination(self, name: str) -> None:
        mapping = {"home": self._home, "report": self._report, "extensions": self._extensions}
        widget = mapping.get(name)
        if widget is not None:
            self._tabs.setCurrentWidget(widget)

    def current_destination(self) -> str:
        widget = self._tabs.currentWidget()
        if widget is self._report:
            return "report"
        if widget is self._extensions:
            return "extensions"
        return "home"
