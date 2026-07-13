"""Desktop-SDK error taxonomy over the shared engineering error types.

All failures crossing the package's public API are expressed as
``reveng_errors.EngError`` (often via ``Result``). ``guard`` is the single
boundary that converts internal exceptions so no raw exception escapes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from reveng_errors import EngError, Result, err

__all__ = [
    "DesktopError",
    "NotFoundError",
    "JobNotReadyError",
    "RequestError",
    "ServiceError",
    "ServiceUnavailableError",
    "PersistenceError",
    "make_error",
    "guard",
]

T = TypeVar("T")


class DesktopError(Exception):
    """Base exception for desktop-integration failures."""

    code: str = "DESKTOP.ERROR"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_eng_error(self) -> EngError:
        return err(self.code, self.message, **self.context)


class NotFoundError(DesktopError):
    """The server returned 404 (e.g. unknown job id)."""

    code = "DESKTOP.NOT_FOUND"


class JobNotReadyError(DesktopError):
    """The server returned 409 (job not yet completed)."""

    code = "DESKTOP.JOB_NOT_READY"


class RequestError(DesktopError):
    """The server rejected the request (413/422) or the client-side request
    was otherwise invalid (e.g. a poll_job timeout)."""

    code = "DESKTOP.REQUEST"


class ServiceError(DesktopError):
    """The server returned an unexpected 4xx/5xx status."""

    code = "DESKTOP.SERVICE"


class ServiceUnavailableError(DesktopError):
    """The service could not be reached at all (connection refused, DNS
    failure, timeout) -- distinct from an HTTP-status error so callers can
    tell "unreachable" from "reachable but erroring"."""

    code = "DESKTOP.SERVICE_UNAVAILABLE"


class PersistenceError(DesktopError):
    """Preferences/workspace JSON state could not be read or written."""

    code = "DESKTOP.PERSISTENCE"


def make_error(code: str, message: str, **context: Any) -> EngError:
    """Construct an ``EngError`` with a desktop-namespaced code."""

    return err(code, message, **context)


def guard(fn: Callable[[], T]) -> Result[T]:
    """Run ``fn`` and capture any failure as a ``Result``.

    ``DesktopError`` maps to its declared code; any other exception maps to
    ``DESKTOP.UNEXPECTED``. This keeps raw exceptions off the public API.
    """

    try:
        return Result.success(fn())
    except DesktopError as exc:
        return Result.failure(exc.to_eng_error())
    except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
        return Result.failure(
            err("DESKTOP.UNEXPECTED", str(exc), exception_type=type(exc).__name__)
        )
