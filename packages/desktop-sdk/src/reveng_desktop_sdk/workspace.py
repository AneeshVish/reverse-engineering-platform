"""Workspace model: projects, open binaries (recent files), preferences.

Persisted as JSON at ``~/.reveng/desktop/workspace.json``, separately from
``preferences.json`` (see ``preferences.py``) -- deliberately split so the two
stores never race to own the same JSON keys. ``Workspace.preferences`` is
composed at load time, not re-serialized here. No analysis state lives here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import PersistenceError
from .preferences import Preferences
from .project import Project

__all__ = ["Workspace", "WorkspaceStore", "DEFAULT_WORKSPACE_PATH"]

DEFAULT_WORKSPACE_PATH = Path.home() / ".reveng" / "desktop" / "workspace.json"


def _project_to_dict(project: Project) -> dict[str, Any]:
    return {
        "project_id": project.project_id,
        "name": project.name,
        "root_path": str(project.root_path),
        "artifacts": list(project.artifacts),
        "created_at": project.created_at,
    }


def _project_from_dict(data: dict[str, Any]) -> Project:
    return Project(
        project_id=data["project_id"],
        name=data["name"],
        root_path=Path(data["root_path"]),
        artifacts=tuple(data.get("artifacts", ())),
        created_at=data.get("created_at", 0.0),
    )


@dataclass
class Workspace:
    """Mutable aggregate: projects, recent files, and the active preferences."""

    projects: dict[str, Project] = field(default_factory=dict)
    recent_files: list[str] = field(default_factory=list)
    preferences: Preferences = field(default_factory=Preferences)

    def add_project(self, project: Project) -> None:
        self.projects[project.project_id] = project
        self.touch_recent(str(project.root_path))

    def remove_project(self, project_id: str) -> None:
        self.projects.pop(project_id, None)

    def touch_recent(self, path: str) -> None:
        """Move ``path`` to the front of recent files, capped and de-duped."""

        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        limit = max(self.preferences.recent_project_limit, 0)
        del self.recent_files[limit:]


class WorkspaceStore:
    """JSON persistence for ``Workspace`` (projects + recent_files only)."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_WORKSPACE_PATH

    def load(self, *, preferences: Preferences | None = None) -> Workspace:
        if not self._path.exists():
            return Workspace(preferences=preferences or Preferences())
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PersistenceError("failed to read workspace", path=str(self._path)) from exc

        projects = {
            project_id: _project_from_dict(project_data)
            for project_id, project_data in data.get("projects", {}).items()
        }
        recent_files = list(data.get("recent_files", []))
        return Workspace(
            projects=projects, recent_files=recent_files, preferences=preferences or Preferences()
        )

    def save(self, workspace: Workspace) -> None:
        payload = {
            "projects": {
                project_id: _project_to_dict(project)
                for project_id, project in workspace.projects.items()
            },
            "recent_files": workspace.recent_files,
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            raise PersistenceError("failed to write workspace", path=str(self._path)) from exc
