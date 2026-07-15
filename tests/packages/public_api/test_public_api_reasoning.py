"""Public-api tests: GET /jobs/{id}/reasoning."""

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


def test_reasoning_matches_the_shape_of_the_canonical_serializer() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        response = client.get(f"/jobs/{job_id}/reasoning")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"inferences"}
    for inference in payload["inferences"]:
        assert set(inference) == {
            "id",
            "kind",
            "state",
            "subject",
            "fact",
            "explanation",
            "properties",
        }
        assert set(inference["explanation"]) == {
            "rule_id",
            "output_fact",
            "input_evidence",
            "input_nodes",
            "input_edges",
        }


def test_reasoning_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs/does-not-exist/reasoning")
    assert response.status_code == 404
