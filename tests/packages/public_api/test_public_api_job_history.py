"""Public-api tests: GET /jobs -- filtering, newest-first ordering, pagination."""

from __future__ import annotations

import time

from _public_api_helpers import TEST_ARTIFACT_BYTES, build_test_service, make_test_app
from fastapi.testclient import TestClient
from reveng_public_api import FixedClock


def _submit(client: TestClient, source_ref: str) -> str:
    response = client.post(
        "/jobs",
        files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
        data={"source_ref": source_ref},
    )
    return response.json()["job_id"]


def _poll_until_terminal(client: TestClient, job_id: str, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] in ("completed", "failed", "cancelled"):
            return status
        time.sleep(0.02)
    return status


def test_list_jobs_is_newest_first() -> None:
    clock = FixedClock()
    service = build_test_service(clock=clock)
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        first = _submit(client, "s")
        _poll_until_terminal(client, first)
        clock.advance(1.0)
        second = _submit(client, "s")
        _poll_until_terminal(client, second)

        response = client.get("/jobs")
        assert response.status_code == 200
        job_ids = [job["job_id"] for job in response.json()["jobs"]]
        assert job_ids.index(second) < job_ids.index(first)


def test_list_jobs_filters_by_project_alias_for_source_ref() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        target = _submit(client, "proj-a")
        _submit(client, "proj-b")
        _poll_until_terminal(client, target)

        response = client.get("/jobs", params={"project": "proj-a"})
        payload = response.json()
        assert payload["total_count"] == 1
        assert payload["jobs"][0]["job_id"] == target
        assert payload["jobs"][0]["source_ref"] == "proj-a"


def test_list_jobs_filters_by_artifact() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _submit(client, "s")
        status = _poll_until_terminal(client, job_id)
        artifact_ref = status["artifact_ref"]
        assert artifact_ref

        response = client.get("/jobs", params={"artifact": artifact_ref})
        payload = response.json()
        assert payload["total_count"] == 1
        assert payload["jobs"][0]["job_id"] == job_id

        empty = client.get("/jobs", params={"artifact": "does-not-exist"})
        assert empty.json()["total_count"] == 0


def test_list_jobs_filters_by_state() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _submit(client, "s")
        _poll_until_terminal(client, job_id)

        completed = client.get("/jobs", params={"state": "completed"})
        assert completed.json()["total_count"] >= 1

        failed = client.get("/jobs", params={"state": "failed"})
        assert all(job["job_id"] != job_id for job in failed.json()["jobs"])


def test_list_jobs_unknown_state_returns_422() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs", params={"state": "not-a-state"})
    assert response.status_code == 422


def test_list_jobs_pagination() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_ids = [_submit(client, "s") for _ in range(3)]
        for job_id in job_ids:
            _poll_until_terminal(client, job_id)

        page1 = client.get("/jobs", params={"limit": 2, "offset": 0}).json()
        page2 = client.get("/jobs", params={"limit": 2, "offset": 2}).json()

        assert page1["total_count"] == page2["total_count"]
        assert page1["total_count"] >= 3
        assert len(page1["jobs"]) == 2
        returned_ids = {job["job_id"] for job in page1["jobs"]} | {
            job["job_id"] for job in page2["jobs"]
        }
        assert set(job_ids) <= returned_ids


def test_job_detail_reports_phase_timings_and_progress() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _submit(client, "s")
        status = _poll_until_terminal(client, job_id)

    assert status["state"] == "completed"
    assert status["progress_percent"] == 100.0
    assert status["report_available"] is True
    phases = [p["phase"] for p in status["phases"]]
    assert phases == [
        "producer",
        "static_analysis",
        "knowledge_graph",
        "reasoning",
        "investigation",
        "reporting",
    ]
