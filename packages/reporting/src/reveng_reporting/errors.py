"""Reporting error taxonomy over the shared engineering error types.

All failures crossing the package's public API are expressed as
``reveng_errors.EngError`` (often via ``Result``). ``guard`` is the single
boundary that converts internal exceptions so no raw exception escapes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from reveng_errors import EngError, Result, err

__all__ = [
    "ReportingError",
    "BuilderError",
    "ValidationError",
    "SerializationError",
    "TemplateError",
    "make_error",
    "guard",
]

T = TypeVar("T")


class ReportingError(Exception):
    """Base exception for reporting-layer failures."""

    code: str = "REPORT.ERROR"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_eng_error(self) -> EngError:
        return err(self.code, self.message, **self.context)


class BuilderError(ReportingError):
    code = "REPORT.BUILDER"


class ValidationError(ReportingError):
    code = "REPORT.VALIDATION"


class SerializationError(ReportingError):
    code = "REPORT.SERIALIZATION"


class TemplateError(ReportingError):
    code = "REPORT.TEMPLATE"


def make_error(code: str, message: str, **context: Any) -> EngError:
    """Construct an ``EngError`` with a reporting-namespaced code."""

    return err(code, message, **context)


def guard(fn: Callable[[], T]) -> Result[T]:
    """Run ``fn`` and capture any failure as a ``Result``.

    ``ReportingError`` maps to its declared code; any other exception maps to
    ``REPORT.UNEXPECTED``. This keeps raw exceptions off the public API.
    """

    try:
        return Result.success(fn())
    except ReportingError as exc:
        return Result.failure(exc.to_eng_error())
    except Exception as exc:  # noqa: BLE001 - deliberate boundary conversion
        return Result.failure(
            err("REPORT.UNEXPECTED", str(exc), exception_type=type(exc).__name__)
        )
