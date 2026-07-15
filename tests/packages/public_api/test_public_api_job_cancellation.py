"""Public-api tests: DELETE /jobs/{id} -- cooperative cancellation.

Cancellation is cooperative, not preemptive: the orchestrator only observes
``cancel_requested`` at a phase boundary. ``build_gated_service`` blocks the
static-analysis phase on a ``threading.Event`` so tests can deterministically
catch a job mid-flight (RUNNING, past the producer boundary) before choosing
whether to let it proceed or cancel it.
"""

from __future__ import annotations

import time

from _public_api_helpers import TEST_ARTIFACT_BYTES, build_gated_service, make_test_app
from fastapi.testclient import TestClient


def _wait_for_state(client: TestClient, job_id: str, state: str, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] == state:
            return status
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {state}: last saw {status}")


def test_cancel_pending_job_is_immediate() -> None:
    service, gate = build_gated_service(max_workers=1)
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        first = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        _wait_for_state(client, first, "running")

        # The pool has exactly one worker, busy with `first` -> `second` must
        # still be PENDING.
        second = client.post(
            "/jobs", files={"file": ("t2.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        assert client.get(f"/jobs/{second}").json()["state"] == "pending"

        cancel = client.delete(f"/jobs/{second}")
        assert cancel.status_code == 200
        assert cancel.json()["state"] == "cancelled"

        gate.set()
        _wait_for_state(client, first, "completed")


def test_cancel_running_job_transitions_at_next_phase_boundary() -> None:
    service, gate = build_gated_service()
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        status = _wait_for_state(client, job_id, "running")
        assert status["current_phase"] == "static_analysis"

        cancel = client.delete(f"/jobs/{job_id}")
        assert cancel.status_code == 200
        assert cancel.json()["state"] == "running"  # still finishing the current phase
        assert cancel.json()["cancel_requested"] is True

        gate.set()  # let static_analysis finish so the next boundary observes the flag
        final = _wait_for_state(client, job_id, "cancelled")
        assert final["error"] is None


def test_cancel_completed_job_returns_409() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        _wait_for_state(client, job_id, "completed")

        response = client.delete(f"/jobs/{job_id}")
        assert response.status_code == 409


def test_cancel_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.delete("/jobs/does-not-exist")
    assert response.status_code == 404


def test_status_snapshots_are_isolated_from_live_phase_updates() -> None:
    """A status snapshot taken mid-run must not share the mutable ``phases``
    dict with the live job the worker thread keeps inserting into -- iterating
    a stale snapshot while the pipeline advances must be safe."""

    service, gate = build_gated_service()
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        _wait_for_state(client, job_id, "running")

        snapshot = service.job_manager.status(job_id)
        phases_before = dict(snapshot.phases)

        gate.set()
        _wait_for_state(client, job_id, "completed")

        # The earlier snapshot must be untouched by the completions that
        # happened after it was taken; only a fresh snapshot sees them.
        assert snapshot.phases == phases_before
        assert len(service.job_manager.status(job_id).phases) == 6


def test_cancel_twice_returns_409_on_second_call() -> None:
    service, gate = build_gated_service()
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        job_id = client.post(
            "/jobs", files={"file": ("t.bin", TEST_ARTIFACT_BYTES)}, data={"source_ref": "s"}
        ).json()["job_id"]
        _wait_for_state(client, job_id, "running")

        first_cancel = client.delete(f"/jobs/{job_id}")
        assert first_cancel.status_code == 200

        gate.set()
        _wait_for_state(client, job_id, "cancelled")

        second_cancel = client.delete(f"/jobs/{job_id}")
        assert second_cancel.status_code == 409
