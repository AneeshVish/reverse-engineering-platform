"""Desktop-sdk tests: DesktopClient over the real 6 endpoints + error mapping."""

from __future__ import annotations

import httpx
import pytest
from _desktop_helpers import (
    TEST_ARTIFACT_BYTES,
    failing_transport_client,
    make_test_client,
    mock_status_client,
)
from reveng_desktop_sdk.errors import (
    JobNotReadyError,
    NotFoundError,
    RequestError,
    ServiceError,
    ServiceUnavailableError,
)


def test_upload() -> None:
    client = make_test_client()
    response = client.upload(TEST_ARTIFACT_BYTES, source_ref="s")
    assert response.artifact_ref
    assert response.artifact_type


def test_submit_job_and_poll_to_completion() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    assert submission.job_id

    status = client.poll_job(submission.job_id, interval=0.02, timeout=5.0)
    assert status.state == "completed"
    assert status.error is None


def test_job_report_after_completion() -> None:
    client = make_test_client()
    submission = client.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    client.poll_job(submission.job_id, interval=0.02, timeout=5.0)

    report = client.job_report(submission.job_id)
    assert report.job_id == submission.job_id
    assert report.format == "json"
    assert report.content


def test_plugins() -> None:
    client = make_test_client()
    plugins = client.plugins()
    assert len(plugins) > 0
    assert all(p.identifier for p in plugins)


def test_health() -> None:
    client = make_test_client()
    health = client.health()
    assert health.state == "healthy"


def test_poll_job_timeout_raises_request_error() -> None:
    client = mock_status_client(200, {"job_id": "x", "state": "running", "submitted_at": 0.0})
    with pytest.raises(RequestError):
        client.poll_job("x", interval=0.01, timeout=0.05)


def test_404_maps_to_not_found_error() -> None:
    client = mock_status_client(404, {"detail": "not found"})
    with pytest.raises(NotFoundError):
        client.job_status("missing")


def test_409_maps_to_job_not_ready_error() -> None:
    client = mock_status_client(409, {"detail": "job is not completed"})
    with pytest.raises(JobNotReadyError):
        client.job_report("x")


def test_413_maps_to_request_error() -> None:
    client = mock_status_client(413, {"detail": "too big"})
    with pytest.raises(RequestError):
        client.upload(TEST_ARTIFACT_BYTES, source_ref="s")


def test_422_maps_to_request_error() -> None:
    client = mock_status_client(422, {"detail": "invalid"})
    with pytest.raises(RequestError):
        client.upload(TEST_ARTIFACT_BYTES, source_ref="s")


def test_500_maps_to_service_error() -> None:
    client = mock_status_client(500, {"detail": "boom"})
    with pytest.raises(ServiceError):
        client.health()


def test_connection_failure_maps_to_service_unavailable() -> None:
    client = failing_transport_client(httpx.ConnectError("refused"))
    with pytest.raises(ServiceUnavailableError):
        client.health()
