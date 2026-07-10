"""Substrate tests: error taxonomy and boundary conversion."""

from __future__ import annotations

import pytest
from reveng_core_substrate import (
    ConfigError,
    ContainerError,
    ContextError,
    EventError,
    LifecycleError,
    RegistryError,
    ServiceContainer,
    SubstrateError,
    guard,
    make_error,
)


def test_error_codes_are_namespaced() -> None:
    assert SubstrateError.code == "SUBSTRATE.ERROR"
    assert LifecycleError.code == "SUBSTRATE.LIFECYCLE"
    assert ContainerError.code == "SUBSTRATE.CONTAINER"
    assert RegistryError.code == "SUBSTRATE.REGISTRY"
    assert ContextError.code == "SUBSTRATE.CONTEXT"
    assert EventError.code == "SUBSTRATE.EVENT"
    assert ConfigError.code == "SUBSTRATE.CONFIG"


def test_substrate_error_carries_context() -> None:
    exc = ContainerError("nope", key="svc")
    eng = exc.to_eng_error()
    assert eng.code == "SUBSTRATE.CONTAINER"
    assert eng.message == "nope"
    assert eng.context["key"] == "svc"


def test_make_error() -> None:
    eng = make_error("SUBSTRATE.X", "msg", a=1)
    assert eng.code == "SUBSTRATE.X"
    assert eng.context["a"] == 1


def test_guard_success() -> None:
    result = guard(lambda: 42)
    assert result.ok
    assert result.value == 42
    assert result.error is None


def test_guard_converts_substrate_error() -> None:
    def fail() -> int:
        raise LifecycleError("bad state", state="created")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "SUBSTRATE.LIFECYCLE"
    assert result.error.context["state"] == "created"


def test_guard_converts_unexpected_exception() -> None:
    def fail() -> int:
        raise ValueError("raw")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "SUBSTRATE.UNEXPECTED"
    assert result.error.context["exception_type"] == "ValueError"


def test_guard_wraps_real_public_api_failure() -> None:
    """A raw exception never escapes when the public API is called through guard."""
    container = ServiceContainer()
    result = guard(lambda: container.resolve("missing"))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "SUBSTRATE.CONTAINER"


def test_substrate_errors_are_exceptions() -> None:
    with pytest.raises(SubstrateError):
        raise RegistryError("x")
