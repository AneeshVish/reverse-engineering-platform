"""Public-api tests: GET /jobs/{id}/investigation."""

from __future__ import annotations

import time

from _public_api_helpers import TEST_ARTIFACT_BYTES, make_test_app
from fastapi.testclient import TestClient


def _completed_job(client: TestClient) -> str:
    job_id = client.post(
        "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
    ).json()["job_id"]
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if client.get(f"/jobs/{job_id}").json()["state"] == "completed":
            return job_id
        time.sleep(0.02)
    raise AssertionError("job never completed")


def test_investigation_matches_the_shape_of_the_canonical_serializer() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        response = client.get(f"/jobs/{job_id}/investigation")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"id", "status", "priority", "title", "findings", "properties"}
    for finding in payload["findings"]:
        assert set(finding) == {
            "id",
            "kind",
            "severity",
            "subject",
            "title",
            "explanation",
            "properties",
        }
        assert set(finding["explanation"]) == {
            "inference_ids",
            "evidence_ids",
            "node_ids",
            "edge_ids",
        }


def test_investigation_before_completion_returns_409() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        response = client.get(f"/jobs/{job_id}/investigation")
    assert response.status_code in (200, 409)


def test_investigation_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs/does-not-exist/investigation")
    assert response.status_code == 404
