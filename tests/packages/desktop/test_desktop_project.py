"""Desktop-sdk tests: the immutable Project model."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from _desktop_helpers import deterministic_clock
from reveng_desktop_sdk.project import Project


def test_project_id_is_content_deterministic(tmp_path: Path) -> None:
    a = Project.create(tmp_path, clock=deterministic_clock())
    b = Project.create(tmp_path, clock=deterministic_clock())
    assert a.project_id == b.project_id


def test_different_paths_get_different_ids(tmp_path: Path) -> None:
    a = Project.create(tmp_path / "one", clock=deterministic_clock())
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    b = Project.create(tmp_path / "two", clock=deterministic_clock())
    assert a.project_id != b.project_id


def test_default_name_is_directory_name(tmp_path: Path) -> None:
    project_dir = tmp_path / "my-project"
    project_dir.mkdir()
    project = Project.create(project_dir)
    assert project.name == "my-project"


def test_project_is_frozen(tmp_path: Path) -> None:
    project = Project.create(tmp_path)
    with pytest.raises(dataclasses.FrozenInstanceError):
        project.name = "renamed"  # type: ignore[misc]


def test_with_artifact_returns_new_instance(tmp_path: Path) -> None:
    project = Project.create(tmp_path)
    updated = project.with_artifact("job-000000000000")
    assert updated is not project
    assert updated.artifacts == ("job-000000000000",)
    assert project.artifacts == ()


def test_with_artifact_is_idempotent(tmp_path: Path) -> None:
    project = Project.create(tmp_path).with_artifact("a")
    same = project.with_artifact("a")
    assert same is project
