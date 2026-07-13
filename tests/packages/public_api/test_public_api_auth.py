"""Public-api tests: the authentication hook is present but permissive."""

from __future__ import annotations

from _public_api_helpers import make_test_app
from fastapi.testclient import TestClient
from reveng_public_api import AllowAllAuthHook


def test_no_authorization_header_still_succeeds() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/plugins")
    assert response.status_code == 200


def test_arbitrary_bearer_token_still_succeeds() -> None:
    app, _ = make_test_app()
    with TestClient(app) as client:
        response = client.get("/plugins", headers={"Authorization": "Bearer nonsense-token"})
    assert response.status_code == 200


def test_allow_all_hook_returns_anonymous_principal() -> None:
    hook = AllowAllAuthHook()
    principal = hook.authenticate(None)
    assert principal is not None
    assert principal.identifier == "anonymous"

    token_principal = hook.authenticate("some-token")
    assert token_principal is not None
    assert token_principal.identifier == "anonymous"
