"""Public API error taxonomy over the shared engineering error types.

All failures crossing the package's public API are expressed as
``reveng_errors.EngError`` (often via ``Result``). ``guard`` is the single
boundary that converts internal exceptions so no raw exception escapes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from reveng_errors import EngError, Result, err

__all__ = [
    "PublicApiError",
    "RequestError",
    "UploadError",
    "JobError",
    "OrchestrationError",
    "NotFoundError",
    "AuthError",
    "make_error",
    "guard",
]

T = TypeVar("T")


class PublicApiError(Exception):
    """Base exception for public API / service layer failures."""

    code: str = "PUBLIC_API.ERROR"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_eng_error(self) -> EngError:
        return err(self.code, self.message, **self.context)


class RequestError(PublicApiError):
    code = "PUBLIC_API.REQUEST"


class UploadError(PublicApiError):
    code = "PUBLIC_API.UPLOAD"


class JobError(PublicApiError):
    code = "PUBLIC_API.JOB"


class OrchestrationError(PublicApiError):
    code = "PUBLIC_API.ORCHESTRATION"


class NotFoundError(PublicApiError):
    code = "PUBLIC_API.NOT_FOUND"


class AuthError(PublicApiError):
    code = "PUBLIC_API.AUTH"


def make_error(code: str, message: str, **context: Any) -> EngError:
    """Construct an ``EngError`` with a public-api-namespaced code."""

    return err(code, message, **context)


def guard(fn: Callable[[], T]) -> Result[T]:
    """Run ``fn`` and capture any failure as a ``Result``.

    ``PublicApiError`` maps to its declared code; any other exception maps to
    ``PUBLIC_API.UNEXPECTED``. This keeps raw exceptions off the public API.
    """

    try:
        return Result.success(fn())
    except PublicApiError as exc:
        return Result.failure(exc.to_eng_error())
    except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
        return Result.failure(
            err("PUBLIC_API.UNEXPECTED", str(exc), exception_type=type(exc).__name__)
        )
