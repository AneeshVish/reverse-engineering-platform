"""Shared test fixtures for the desktop-sdk suite."""

from __future__ import annotations

from collections.abc import Callable

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from reveng_desktop_sdk.client import DesktopClient
from reveng_public_api import create_app

# Recognizable as a PE-ish header so the reference producer classifies it
# deterministically rather than falling back to UNKNOWN/RAW_BINARY.
TEST_ARTIFACT_BYTES = b"MZ" + b"A" * 512


def build_test_app() -> FastAPI:
    """A real, fully-wired reveng_public_api service."""

    return create_app()


def make_test_client(app: FastAPI | None = None) -> DesktopClient:
    """A DesktopClient backed by a real in-process ASGI app.

    ``fastapi.testclient.TestClient`` (a genuine ``httpx.Client`` subclass
    that bridges to the ASGI app internally) is used rather than
    ``httpx.ASGITransport``, since ``ASGITransport`` only implements the
    async request path and cannot back a sync ``httpx.Client``.
    """

    http = TestClient(app or build_test_app())
    http.__enter__()  # runs the app's lifespan; matches `with TestClient(app):`
    return DesktopClient(http_client=http)


def mock_status_client(status_code: int, payload: object) -> DesktopClient:
    """A DesktopClient whose every request returns a canned status/body --
    for isolated, deterministic HTTP-error-mapping tests with no live app."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload)

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    return DesktopClient(http_client=http)


def failing_transport_client(exc: Exception) -> DesktopClient:
    """A DesktopClient whose transport always raises -- for
    ServiceUnavailableError mapping tests."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    return DesktopClient(http_client=http)


def deterministic_clock(start: float = 0.0) -> Callable[[], float]:
    """A monotonically-advancing fake clock for Project.create() tests."""

    state = {"value": start}

    def clock() -> float:
        state["value"] += 1.0
        return state["value"]

    return clock
