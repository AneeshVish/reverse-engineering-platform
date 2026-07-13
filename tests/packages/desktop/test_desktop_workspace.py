"""Desktop-sdk tests: Workspace aggregate and JSON persistence."""

from __future__ import annotations

import json
from pathlib import Path

from reveng_desktop_sdk.preferences import Preferences
from reveng_desktop_sdk.project import Project
from reveng_desktop_sdk.workspace import Workspace, WorkspaceStore


def test_add_and_remove_project(tmp_path: Path) -> None:
    workspace = Workspace()
    project = Project.create(tmp_path)

    workspace.add_project(project)
    assert workspace.projects[project.project_id] == project

    workspace.remove_project(project.project_id)
    assert project.project_id not in workspace.projects


def test_recent_files_dedup_and_most_recent_first() -> None:
    workspace = Workspace()
    workspace.touch_recent("/a")
    workspace.touch_recent("/b")
    workspace.touch_recent("/a")  # re-touch moves it to front
    assert workspace.recent_files == ["/a", "/b"]


def test_recent_files_capped_by_preferences_limit() -> None:
    workspace = Workspace(preferences=Preferences(recent_project_limit=2))
    workspace.touch_recent("/a")
    workspace.touch_recent("/b")
    workspace.touch_recent("/c")
    assert workspace.recent_files == ["/c", "/b"]


def test_add_project_touches_recent_files(tmp_path: Path) -> None:
    workspace = Workspace()
    project = Project.create(tmp_path)
    workspace.add_project(project)
    assert workspace.recent_files == [str(project.root_path)]


def test_round_trip(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    workspace = Workspace()
    project = Project.create(tmp_path / "proj")
    workspace.add_project(project)

    store.save(workspace)
    loaded = store.load()

    assert loaded.projects[project.project_id].name == project.name
    assert loaded.projects[project.project_id].root_path == project.root_path
    assert loaded.recent_files == workspace.recent_files


def test_store_returns_empty_workspace_when_missing(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    workspace = store.load()
    assert workspace.projects == {}
    assert workspace.recent_files == []


def test_preferences_not_reserialized_into_workspace_json(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    workspace = Workspace(preferences=Preferences(theme="light"))
    store.save(workspace)

    raw = json.loads((tmp_path / "workspace.json").read_text())
    assert "preferences" not in raw
    assert set(raw.keys()) == {"projects", "recent_files"}


def test_load_composes_supplied_preferences(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "workspace.json")
    store.save(Workspace())
    custom_prefs = Preferences(theme="light")

    loaded = store.load(preferences=custom_prefs)
    assert loaded.preferences is custom_prefs
