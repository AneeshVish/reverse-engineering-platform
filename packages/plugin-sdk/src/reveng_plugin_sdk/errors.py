"""Plugin error taxonomy over the shared engineering error types.

All failures crossing the package's public API are expressed as
``reveng_errors.EngError`` (often via ``Result``). ``guard`` is the single
boundary that converts internal exceptions so no raw exception escapes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from reveng_errors import EngError, Result, err

__all__ = [
    "PluginError",
    "RegistrationError",
    "DependencyError",
    "ValidationError",
    "LoadingError",
    "LifecycleError",
    "make_error",
    "guard",
]

T = TypeVar("T")


class PluginError(Exception):
    """Base exception for plugin-framework failures."""

    code: str = "PLUGIN.ERROR"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_eng_error(self) -> EngError:
        return err(self.code, self.message, **self.context)


class RegistrationError(PluginError):
    code = "PLUGIN.REGISTRATION"


class DependencyError(PluginError):
    code = "PLUGIN.DEPENDENCY"


class ValidationError(PluginError):
    code = "PLUGIN.VALIDATION"


class LoadingError(PluginError):
    code = "PLUGIN.LOADING"


class LifecycleError(PluginError):
    code = "PLUGIN.LIFECYCLE"


def make_error(code: str, message: str, **context: Any) -> EngError:
    """Construct an ``EngError`` with a plugin-namespaced code."""

    return err(code, message, **context)


def guard(fn: Callable[[], T]) -> Result[T]:
    """Run ``fn`` and capture any failure as a ``Result``.

    ``PluginError`` maps to its declared code; any other exception maps to
    ``PLUGIN.UNEXPECTED``. This keeps raw exceptions off the public API.
    """

    try:
        return Result.success(fn())
    except PluginError as exc:
        return Result.failure(exc.to_eng_error())
    except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
        return Result.failure(
            err("PLUGIN.UNEXPECTED", str(exc), exception_type=type(exc).__name__)
        )
