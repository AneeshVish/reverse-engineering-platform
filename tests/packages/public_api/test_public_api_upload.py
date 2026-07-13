"""Public-api tests: the upload endpoint."""

from __future__ import annotations

from _public_api_helpers import TEST_ARTIFACT_BYTES, build_test_service, make_test_app
from fastapi.testclient import TestClient


def test_upload_round_trip() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.post(
            "/artifacts",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "smoke"},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["artifact_ref"]
    assert body["artifact_type"]


def test_upload_is_content_deterministic() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        first = client.post(
            "/artifacts",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "a"},
        ).json()
        second = client.post(
            "/artifacts",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "b"},
        ).json()
    # Content-derived artifact identity does not depend on source_ref.
    assert first["artifact_ref"] == second["artifact_ref"]


def test_upload_over_max_bytes_returns_413() -> None:
    service = build_test_service()
    service.config.values["max_upload_bytes"] = 4
    app, _ = make_test_app(service)
    with TestClient(app) as client:
        response = client.post(
            "/artifacts",
            files={"file": ("t.bin", TEST_ARTIFACT_BYTES)},
            data={"source_ref": "big"},
        )
    assert response.status_code == 413
