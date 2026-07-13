# -*- coding: utf-8 -*-
"""Project Explorer (Phase 016 spec, 10.10) -- renamed from "Workspace Panel".

Analysts think in projects, not workspaces. Backed read-only by the already-
built Desktop SDK ``Workspace``/``Project``/``WorkspaceStore`` (Phase 015) --
this module makes no changes to that package. "Archived" is tracked as a
small, purely local set of project ids (see ``_ArchiveStore``) rather than a
new field on the SDK's own ``Project`` model, so a completed package stays
untouched.

Hierarchy scope (10.10): exposes only Workspace -> Project, the first two
levels of the eventual Workspace -> Project -> Artifact -> {...} hierarchy.
Works fully offline -- ``DesktopManager.workspace`` is local data, populated
independently of backend connectivity.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.gui.icons import icon as qicon
from src.utils.paths import bundle_root, is_frozen, user_data_dir

logger = logging.getLogger(__name__)


def _default_archive_path() -> Path:
    base = user_data_dir() if is_frozen() else bundle_root()
    return base / "archived_projects.json"


class _ArchiveStore:
    """A small local set of archived project ids -- purely additive, no
    changes to the Desktop SDK's own Project/Workspace model."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or _default_archive_path()
        self._archived: set[str] = set()
        self.load()

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._archived = set(data.get("archived_project_ids", []))
        except Exception as e:  # noqa: BLE001 - best-effort load
            logger.error("Failed to load archived projects: %s", e)

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({"archived_project_ids": sorted(self._archived)}, indent=2),
                encoding="utf-8",
            )
        except Exception as e:  # noqa: BLE001 - best-effort save
            logger.error("Failed to save archived projects: %s", e)

    def is_archived(self, project_id: str) -> bool:
        return project_id in self._archived

    def archive(self, project_id: str) -> None:
        self._archived.add(project_id)
        self.save()

    def unarchive(self, project_id: str) -> None:
        self._archived.discard(project_id)
        self.save()


class ProjectExplorer(QWidget):
    """Project A / Project B / Project C, with an Archived section."""

    project_open_requested = pyqtSignal(str)  # root_path

    def __init__(self, desktop_manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = desktop_manager
        self._archives = _ArchiveStore()

        layout = QVBoxLayout(self)
        heading = QLabel("Project Explorer")
        heading.setObjectName("Heading")
        layout.addWidget(heading)

        layout.addWidget(QLabel("Active", objectName="Dim"))
        self._active_list = QListWidget()
        self._active_list.itemDoubleClicked.connect(self._on_open_active)
        layout.addWidget(self._active_list)

        actions = QHBoxLayout()
        archive_btn = QPushButton("Archive")
        archive_btn.setIcon(qicon("fa5s.box"))
        archive_btn.clicked.connect(self._on_archive_selected)
        actions.addWidget(archive_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        layout.addWidget(QLabel("Archived", objectName="Dim"))
        self._archived_list = QListWidget()
        self._archived_list.itemDoubleClicked.connect(self._on_open_archived)
        layout.addWidget(self._archived_list)

        unarchive_btn = QPushButton("Unarchive selected")
        unarchive_btn.clicked.connect(self._on_unarchive_selected)
        layout.addWidget(unarchive_btn)

        self.refresh()

    def refresh(self) -> None:
        self._active_list.clear()
        self._archived_list.clear()
        for project_id, project in self._manager.workspace.projects.items():
            item = QListWidgetItem(f"{project.name}  —  {project.root_path}")
            item.setData(1000, project_id)
            item.setData(1001, str(project.root_path))
            if self._archives.is_archived(project_id):
                self._archived_list.addItem(item)
            else:
                self._active_list.addItem(item)

    def _on_open_active(self, item: QListWidgetItem) -> None:
        self.project_open_requested.emit(item.data(1001))

    def _on_open_archived(self, item: QListWidgetItem) -> None:
        self.project_open_requested.emit(item.data(1001))

    def _on_archive_selected(self) -> None:
        item = self._active_list.currentItem()
        if item is None:
            return
        self._archives.archive(item.data(1000))
        self.refresh()

    def _on_unarchive_selected(self) -> None:
        item = self._archived_list.currentItem()
        if item is None:
            return
        self._archives.unarchive(item.data(1000))
        self.refresh()
