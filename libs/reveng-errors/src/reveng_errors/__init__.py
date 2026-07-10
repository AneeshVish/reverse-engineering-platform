"""Engineering error taxonomy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

__version__ = "0.1.0"

T = TypeVar("T")


@dataclass(frozen=True)
class EngError:
    code: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "context": dict(self.context)}


@dataclass
class Result(Generic[T]):
    value: T | None = None
    error: EngError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @classmethod
    def success(cls, value: T) -> Result[T]:
        return cls(value=value, error=None)

    @classmethod
    def failure(cls, error: EngError) -> Result[T]:
        return cls(value=None, error=error)


def err(code: str, message: str, **context: Any) -> EngError:
    return EngError(code=code, message=message, context=context)
