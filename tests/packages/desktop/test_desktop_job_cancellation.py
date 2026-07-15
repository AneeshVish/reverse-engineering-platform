"""Desktop-sdk tests: DesktopClient.cancel_job -- response mapping.

Racing a real orchestrator into RUNNING deterministically needs the gated
service machinery that lives in the public-api test suite (this package
intentionally never imports backend-analysis packages, see
``test_desktop_dependency_hygiene.py``); here we cover the client's own
mechanics with the same isolated-mock pattern ``test_desktop_client.py`` uses
for the other status-code mappings, plus one real end-to-end terminal-state
409 against a genuinely completed job.
"""

from __future__ import annotations

import pytest
from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client, mock_status_client
from reveng_desktop_sdk.errors import JobNotReadyError, NotFoundError


def test_cancel_job_parses_a_successful_response() -> None:
    client = mock_status_client(
        200,
        {
            "job_id": "job-1",
            "state": "cancelled",
            "submitted_at": 0.0,
            "started_at": 0.0,
            "finished_at": 1.0,
            "error": None,
            "source_ref": "s",
            "artifact_ref": None,
            "current_phase": "static_analysis",
            "phases": [],
            "progress_percent": 16.67,
            "estimated_remaining": None,
            "report_available": False,
            "cancel_requested": True,
        },
    )
    detail = client.cancel_job("job-1")
    assert detail.state == "cancelled"
    assert detail.cancel_requested is True


def test_cancel_completed_job_maps_409_to_job_not_ready_error() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    with pytest.raises(JobNotReadyError):
        client.cancel_job(submission.job_id)


def test_cancel_unknown_job_maps_404_to_not_found_error() -> None:
    client = mock_status_client(404, {"detail": "job not found"})
    with pytest.raises(NotFoundError):
        client.cancel_job("does-not-exist")
