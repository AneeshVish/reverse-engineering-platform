"""Desktop-sdk tests: DesktopClient/DesktopManager get_evidence."""

from __future__ import annotations

from pathlib import Path

from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client
from reveng_desktop_sdk.manager import DesktopManager
from reveng_desktop_sdk.preferences import PreferencesStore
from reveng_desktop_sdk.service import DesktopService
from reveng_desktop_sdk.workspace import WorkspaceStore


def test_client_get_evidence() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    evidence = client.get_evidence(submission.job_id)
    assert len(evidence.evidence) > 0


def test_manager_get_evidence(tmp_path: Path) -> None:
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

    evidence = manager.get_evidence(submission.job_id)
    assert len(evidence.evidence) > 0

    manager.shutdown()
