"""Typed, persisted user preferences.

Genuinely global: survives across workspace resets (theme, autosave,
recent-project limit, the API endpoint to connect to, window geometry).
Persisted as JSON at ``~/.reveng/desktop/preferences.json`` -- a fresh,
minimal design with no in-repo precedent, since the legacy ``Settings``
class is deliberately not reused.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .errors import PersistenceError

__all__ = ["Preferences", "PreferencesStore", "DEFAULT_PREFERENCES_PATH"]

DEFAULT_PREFERENCES_PATH = Path.home() / ".reveng" / "desktop" / "preferences.json"


@dataclass
class Preferences:
    """Typed, user-facing UX settings."""

    theme: str = "dark"
    autosave: bool = True
    recent_project_limit: int = 10
    api_base_url: str = "http://127.0.0.1:8000"
    window_state: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Preferences:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


class PreferencesStore:
    """JSON persistence for ``Preferences``."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_PREFERENCES_PATH

    def load(self) -> Preferences:
        if not self._path.exists():
            return Preferences()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PersistenceError("failed to read preferences", path=str(self._path)) from exc
        return Preferences.from_dict(data)

    def save(self, preferences: Preferences) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(preferences.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            raise PersistenceError("failed to write preferences", path=str(self._path)) from exc
