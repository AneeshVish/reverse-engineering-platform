"""Desktop-sdk tests: DesktopClient/DesktopManager get_graph."""

from __future__ import annotations

from pathlib import Path

from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client
from reveng_desktop_sdk.manager import DesktopManager
from reveng_desktop_sdk.preferences import PreferencesStore
from reveng_desktop_sdk.service import DesktopService
from reveng_desktop_sdk.workspace import WorkspaceStore


def test_client_get_graph() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    graph = client.get_graph(submission.job_id)
    assert len(graph.nodes) > 0


def test_client_get_graph_with_filters() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    graph = client.get_graph(submission.job_id, node_types="artifact", limit=1)
    assert len(graph.nodes) == 1
    assert graph.nodes[0].kind == "artifact"


def test_manager_get_graph(tmp_path: Path) -> None:
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

    graph = manager.get_graph(submission.job_id)
    assert len(graph.nodes) > 0

    manager.shutdown()
