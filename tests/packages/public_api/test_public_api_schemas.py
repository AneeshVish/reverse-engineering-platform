"""Public-api tests: request validation."""

from __future__ import annotations

import pytest
from _public_api_helpers import make_test_app
from fastapi.testclient import TestClient
from pydantic import ValidationError
from reveng_public_api import JobSubmitResponse


def test_missing_required_field_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        JobSubmitResponse.model_validate({})


def test_upload_without_file_returns_422() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.post("/artifacts", data={"source_ref": "s"})
    assert response.status_code == 422


def test_upload_without_source_ref_returns_422() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.post("/artifacts", files={"file": ("t.bin", b"data")})
    assert response.status_code == 422
