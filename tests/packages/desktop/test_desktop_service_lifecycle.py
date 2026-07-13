"""Desktop-sdk tests: DesktopService attach/reconnect and self-managed subprocess."""

from __future__ import annotations

import socket

import pytest
from _desktop_helpers import make_test_client
from reveng_desktop_sdk.config import DesktopSdkConfig
from reveng_desktop_sdk.errors import ServiceUnavailableError
from reveng_desktop_sdk.service import DesktopService


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_is_running_true_when_attached() -> None:
    service = DesktopService(client=make_test_client())
    assert service.is_running() is True
    assert service.health_state().value == "healthy"


def test_ensure_connected_is_a_noop_when_already_running() -> None:
    service = DesktopService(client=make_test_client())
    service.ensure_connected()  # must not raise
    assert service.is_running() is True


def test_start_raises_when_unreachable_and_not_self_managed() -> None:
    config = DesktopSdkConfig()
    config.values["base_url"] = f"http://127.0.0.1:{_free_port()}"
    config.values["self_manage_process"] = False
    config.values["startup_timeout_seconds"] = 0.5
    service = DesktopService(config)
    with pytest.raises(ServiceUnavailableError):
        service.start()


def test_stop_is_idempotent() -> None:
    service = DesktopService(client=make_test_client())
    service.stop()
    service.stop()  # must not raise the second time


def test_is_running_false_after_stop() -> None:
    service = DesktopService(client=make_test_client())
    assert service.is_running() is True
    service.stop()
    assert service.is_running() is False


def test_self_managed_process_starts_and_stops() -> None:
    """The one deliberately heavier test: spawns a real uvicorn subprocess,
    waits for /health, then stops it and confirms the process exited."""

    config = DesktopSdkConfig()
    config.values["base_url"] = f"http://127.0.0.1:{_free_port()}"
    config.values["self_manage_process"] = True
    config.values["startup_timeout_seconds"] = 20.0
    service = DesktopService(config)

    service.start()
    try:
        assert service.is_running() is True
        assert service._process is not None
        assert service._process.poll() is None  # still alive
    finally:
        service.stop()

    assert service._process is None
    assert service.is_running() is False
