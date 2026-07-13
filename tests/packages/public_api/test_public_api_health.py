"""Public-api tests: health aggregation."""

from __future__ import annotations

from _public_api_helpers import make_test_app
from fastapi.testclient import TestClient


def test_health_endpoint_is_unauthenticated_and_healthy() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "healthy"
    assert body["components"]
    assert all(state == "healthy" for state in body["components"].values())


def test_service_health_reflects_component_count() -> None:
    _, service = make_test_app()
    result = service.health()
    assert result.state.value == "healthy"
    assert str(len(service.application.components)) in result.detail
