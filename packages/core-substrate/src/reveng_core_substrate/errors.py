"""Substrate error taxonomy built on the shared engineering error types.

All failures crossing the substrate's public API are expressed as
``reveng_errors.EngError`` (often wrapped in ``Result``). Raw exceptions raised
internally are converted here so that no uncontrolled exception escapes the
public surface.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from reveng_errors import EngError, Result, err

__all__ = [
    "SubstrateError",
    "LifecycleError",
    "ContainerError",
    "RegistryError",
    "ContextError",
    "EventError",
    "ConfigError",
    "make_error",
    "guard",
]

T = TypeVar("T")


class SubstrateError(Exception):
    """Base exception for substrate-internal failures.

    Public API methods convert these (and any unexpected exception) into
    ``EngError`` / ``Result`` values; ``SubstrateError`` carries a stable code
    so that conversion is lossless.
    """

    code: str = "SUBSTRATE.ERROR"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_eng_error(self) -> EngError:
        return err(self.code, self.message, **self.context)


class LifecycleError(SubstrateError):
    code = "SUBSTRATE.LIFECYCLE"


class ContainerError(SubstrateError):
    code = "SUBSTRATE.CONTAINER"


class RegistryError(SubstrateError):
    code = "SUBSTRATE.REGISTRY"


class ContextError(SubstrateError):
    code = "SUBSTRATE.CONTEXT"


class EventError(SubstrateError):
    code = "SUBSTRATE.EVENT"


class ConfigError(SubstrateError):
    code = "SUBSTRATE.CONFIG"


def make_error(code: str, message: str, **context: Any) -> EngError:
    """Construct an ``EngError`` with a substrate-namespaced code."""

    return err(code, message, **context)


def guard(fn: Callable[[], T]) -> Result[T]:
    """Run ``fn`` and capture any failure as a ``Result``.

    ``SubstrateError`` maps to its declared code; any other exception maps to
    ``SUBSTRATE.UNEXPECTED``. This is the single conversion point that keeps raw
    exceptions from escaping the public API.
    """

    try:
        return Result.success(fn())
    except SubstrateError as exc:
        return Result.failure(exc.to_eng_error())
    except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
        return Result.failure(
            err("SUBSTRATE.UNEXPECTED", str(exc), exception_type=type(exc).__name__)
        )
