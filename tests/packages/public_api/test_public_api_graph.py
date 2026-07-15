"""Public-api tests: GET /jobs/{id}/graph -- node_types/limit filtering.

``depth`` is accepted and validated but a documented no-op in this phase:
there is no seed-node parameter to expand from, and reveng_knowledge_graph
has no traversal primitive.
"""

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


def test_graph_matches_the_shape_of_the_canonical_serializer() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        response = client.get(f"/jobs/{job_id}/graph")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"version", "nodes", "edges"}
    assert payload["nodes"]
    for node in payload["nodes"]:
        assert set(node) == {"id", "kind", "logical_key", "name", "properties"}
    for edge in payload["edges"]:
        assert set(edge) == {"id", "relationship", "source", "target", "properties"}


def test_graph_node_types_filters_and_prunes_dangling_edges() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        unfiltered = client.get(f"/jobs/{job_id}/graph").json()
        filtered = client.get(f"/jobs/{job_id}/graph", params={"node_types": "artifact"}).json()

    assert len(filtered["nodes"]) <= len(unfiltered["nodes"])
    assert all(n["kind"] == "artifact" for n in filtered["nodes"])
    node_ids = {n["id"] for n in filtered["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in filtered["edges"])


def test_graph_limit_caps_node_count() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        unfiltered = client.get(f"/jobs/{job_id}/graph").json()
        limited = client.get(f"/jobs/{job_id}/graph", params={"limit": 1}).json()

    assert len(limited["nodes"]) == min(1, len(unfiltered["nodes"]))


def test_graph_depth_is_accepted_but_a_documented_no_op() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        without_depth = client.get(f"/jobs/{job_id}/graph").json()
        with_depth = client.get(f"/jobs/{job_id}/graph", params={"depth": 2}).json()

    assert without_depth == with_depth


def test_graph_unknown_node_type_returns_422() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        job_id = _completed_job(client)
        response = client.get(f"/jobs/{job_id}/graph", params={"node_types": "not_a_kind"})
    assert response.status_code == 422


def test_graph_unknown_job_returns_404() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/jobs/does-not-exist/graph")
    assert response.status_code == 404
