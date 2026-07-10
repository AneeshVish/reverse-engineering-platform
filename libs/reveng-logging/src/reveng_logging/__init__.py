"""Structured JSON logging facade for engineering tools."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, TextIO

__version__ = "0.1.0"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


class EngLogger:
    def __init__(self, name: str, stream: TextIO | None = None) -> None:
        self.name = name
        self.stream = stream or sys.stderr

    def _emit(self, level: str, message: str, *, event: str | None = None, **fields: Any) -> None:
        payload: dict[str, Any] = {
            "timestamp": _ts(),
            "level": level,
            "logger": self.name,
            "message": message,
        }
        if event is not None:
            payload["event"] = event
        payload.update(fields)
        self.stream.write(json.dumps(payload, default=str) + "\n")
        self.stream.flush()

    def debug(self, message: str, **fields: Any) -> None:
        self._emit("DEBUG", message, **fields)

    def info(self, message: str, *, event: str | None = None, **fields: Any) -> None:
        self._emit("INFO", message, event=event, **fields)

    def warning(self, message: str, *, event: str | None = None, **fields: Any) -> None:
        self._emit("WARNING", message, event=event, **fields)

    def error(self, message: str, *, event: str | None = None, **fields: Any) -> None:
        self._emit("ERROR", message, event=event, **fields)

    def critical(self, message: str, *, event: str | None = None, **fields: Any) -> None:
        self._emit("CRITICAL", message, event=event, **fields)


def get_logger(name: str) -> EngLogger:
    return EngLogger(name)
