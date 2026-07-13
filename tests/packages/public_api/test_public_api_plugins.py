"""Public-api tests: read-only plugin listing."""

from __future__ import annotations

from _public_api_helpers import make_test_app
from fastapi.testclient import TestClient


def test_plugins_endpoint_matches_registry() -> None:
    app, service = make_test_app()
    expected = service.plugin_manager.registry.identifiers()

    with TestClient(app) as client:
        response = client.get("/plugins")

    assert response.status_code == 200
    identifiers = tuple(p["identifier"] for p in response.json())
    assert identifiers == expected
    assert len(response.json()) == len(expected) > 0
