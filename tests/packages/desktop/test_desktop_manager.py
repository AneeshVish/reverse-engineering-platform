"""Desktop-sdk tests: DesktopManager end-to-end -- the automated analogue of
the manual smoke test (open project -> submit -> poll -> report -> plugins
-> health -> close -> shutdown)."""

from __future__ import annotations

from pathlib import Path

from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client
from reveng_desktop_sdk.manager import DesktopManager
from reveng_desktop_sdk.preferences import PreferencesStore
from reveng_desktop_sdk.service import DesktopService
from reveng_desktop_sdk.workspace import WorkspaceStore


def _build_manager(tmp_path: Path) -> DesktopManager:
    service = DesktopService(client=make_test_client())
    return DesktopManager(
        service=service,
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        preferences_store=PreferencesStore(tmp_path / "preferences.json"),
    )


def test_full_flow(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    manager.initialize()

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project = manager.open_project(project_dir, name="demo")
    assert manager.session.current_project == project
    assert project.project_id in manager.workspace.projects

    submission = manager.submit_artifact(TEST_ARTIFACT_BYTES, source_ref="demo-artifact")
    assert submission.job_id

    status = manager.refresh_job(submission.job_id)
    while status.state not in ("completed", "failed"):
        status = manager.refresh_job(submission.job_id)
    assert status.state == "completed"

    report = manager.fetch_report(submission.job_id)
    assert report.content
    assert manager.session.selected_report_job_id == submission.job_id

    plugins = manager.plugins()
    assert len(plugins) > 0

    assert manager.health().state.value == "healthy"
    assert manager.remote_health().state == "healthy"

    manager.close_project()
    assert manager.session.current_project is None
    # Closing does not remove the project from the workspace.
    assert project.project_id in manager.workspace.projects

    manager.shutdown()
    assert (tmp_path / "workspace.json").exists()


def test_submitted_job_id_tracked_on_project(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    manager.initialize()

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    manager.open_project(project_dir)

    submission = manager.submit_artifact(TEST_ARTIFACT_BYTES, source_ref="s")

    current = manager.session.current_project
    assert current is not None
    assert submission.job_id in current.artifacts
    assert manager.workspace.projects[current.project_id].artifacts == current.artifacts

    manager.shutdown()


def test_open_project_without_prior_state_uses_defaults(tmp_path: Path) -> None:
    manager = _build_manager(tmp_path)
    assert manager.preferences.theme == "dark"
    assert manager.workspace.projects == {}
    manager.shutdown()
