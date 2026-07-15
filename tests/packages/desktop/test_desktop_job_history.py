"""Desktop-sdk tests: DesktopClient/DesktopManager job history + detail."""

from __future__ import annotations

from pathlib import Path

from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client
from reveng_desktop_sdk.manager import DesktopManager
from reveng_desktop_sdk.preferences import PreferencesStore
from reveng_desktop_sdk.service import DesktopService
from reveng_desktop_sdk.workspace import WorkspaceStore


def test_client_list_jobs_filters_by_source_ref() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="proj-x")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    listing = client.list_jobs(source_ref="proj-x")
    assert listing.total_count >= 1
    assert any(job.job_id == submission.job_id for job in listing.jobs)
    assert all(job.source_ref == "proj-x" for job in listing.jobs)


def test_client_get_job_returns_richer_detail_than_job_status() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    detail = client.get_job(submission.job_id)
    assert detail.state == "completed"
    assert detail.report_available is True
    assert detail.progress_percent == 100.0
    assert len(detail.phases) == 6


def test_manager_list_jobs_and_get_job(tmp_path: Path) -> None:
    service = DesktopService(client=make_test_client())
    manager = DesktopManager(
        service=service,
        workspace_store=WorkspaceStore(tmp_path / "workspace.json"),
        preferences_store=PreferencesStore(tmp_path / "preferences.json"),
    )
    manager.initialize()

    submission = manager.submit_artifact(TEST_ARTIFACT_BYTES, source_ref="s")
    status = manager.refresh_job(submission.job_id)
    while status.state not in ("completed", "failed"):
        status = manager.refresh_job(submission.job_id)

    listing = manager.list_jobs()
    assert any(job.job_id == submission.job_id for job in listing.jobs)

    detail = manager.get_job(submission.job_id)
    assert detail.job_id == submission.job_id
    assert detail.state == "completed"

    manager.shutdown()
