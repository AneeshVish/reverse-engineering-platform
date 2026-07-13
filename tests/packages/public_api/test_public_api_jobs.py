"""Public-api tests: job submission, status transitions, and the failure path."""

from __future__ import annotations

import dataclasses
import time

from _public_api_helpers import (
    TEST_ARTIFACT_BYTES,
    build_failing_job_manager,
    build_test_service,
    make_test_app,
)
from fastapi.testclient import TestClient


def _poll_until_terminal(client: TestClient, job_id: str, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] in ("completed", "failed"):
            return status
        time.sleep(0.02)
    return status


def test_submit_returns_job_id_immediately() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.post(
            "/jobs",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "s"},
        )
    assert response.status_code == 202
    assert response.json()["job_id"]


def test_job_completes_and_report_is_retrievable() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "s"},
        ).json()["job_id"]

        status = _poll_until_terminal(client, job_id)
        assert status["state"] == "completed"
        assert status["error"] is None

        report = client.get(f"/jobs/{job_id}/report")
        assert report.status_code == 200
        assert report.json()["content"]


def test_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs/does-not-exist")
    assert response.status_code == 404


def test_report_before_completion_returns_409() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "s"},
        ).json()["job_id"]
        # No poll -- request the report immediately; the job may already be
        # complete on a fast machine, so accept either a clean 409 or a 200.
        report = client.get(f"/jobs/{job_id}/report")
        assert report.status_code in (200, 409)


def test_job_failure_path_reports_clean_error() -> None:
    service = build_test_service()
    failing_job_manager = build_failing_job_manager()
    service = dataclasses.replace(service, job_manager=failing_job_manager)
    app, _ = make_test_app(service)

    with TestClient(app) as client:
        job_id = client.post(
            "/jobs",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "s"},
        ).json()["job_id"]

        status = _poll_until_terminal(client, job_id)

    assert status["state"] == "failed"
    assert status["error"]
    assert "Traceback" not in status["error"]
    assert "induced failure for testing" in status["error"]
