"""Public-api tests: GET /jobs/{id}/evidence.

The evidence repository is one shared instance across every job in the
service (constructed once in ``build_service``); the route must filter it
down to the requesting job's own evidence via ``Evidence.artifact_ref``.
"""

from __future__ import annotations

import time

from _public_api_helpers import TEST_ARTIFACT_BYTES, make_test_app
from fastapi.testclient import TestClient


def _completed_job(client: TestClient, content: bytes) -> str:
    job_id = client.post(
        "/jobs", files={"file": ("t.bin", content)}, data={"source_ref": "s"}
    ).json()["job_id"]
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] == "completed":
            return job_id
        time.sleep(0.02)
    raise AssertionError("job never completed")


def test_evidence_matches_the_shape_of_the_canonical_serializer() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client, TEST_ARTIFACT_BYTES)
        response = client.get(f"/jobs/{job_id}/evidence")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"evidence"}
    assert payload["evidence"]
    for record in payload["evidence"]:
        assert set(record) == {
            "id",
            "kind",
            "state",
            "origin",
            "confidence",
            "payload",
            "ir_refs",
            "artifact_ref",
            "metadata",
            "version",
        }


def test_evidence_is_scoped_to_the_requesting_job_only() -> None:
    """Two jobs share one repository -- each job's evidence route must return
    only its own records, not the other job's."""

    app, _ = make_test_app()
    with TestClient(app) as client:
        job_a = _completed_job(client, TEST_ARTIFACT_BYTES)
        job_b = _completed_job(client, TEST_ARTIFACT_BYTES + b"\x00")

        evidence_a = client.get(f"/jobs/{job_a}/evidence").json()["evidence"]
        evidence_b = client.get(f"/jobs/{job_b}/evidence").json()["evidence"]

        artifact_a = client.get(f"/jobs/{job_a}").json()["artifact_ref"]
        artifact_b = client.get(f"/jobs/{job_b}").json()["artifact_ref"]
        assert artifact_a != artifact_b

        assert all(record["artifact_ref"] == artifact_a for record in evidence_a)
        assert all(record["artifact_ref"] == artifact_b for record in evidence_b)
        assert {r["id"] for r in evidence_a}.isdisjoint({r["id"] for r in evidence_b})


def test_evidence_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs/does-not-exist/evidence")
    assert response.status_code == 404
