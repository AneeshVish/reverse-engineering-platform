"""Static-analysis-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the static-analysis-owned surface
from the ``static`` sub-table of ``[tool.reveng]`` (``[tool.reveng.static]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["StaticAnalysisConfig", "load_static_config", "STATIC_DEFAULTS"]

STATIC_DEFAULTS: dict[str, Any] = {
    # Minimum length for the shallow string scan.
    "min_string_length": 4,
}


@dataclass
class StaticAnalysisConfig:
    """Typed view over static-analysis-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(STATIC_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def min_string_length(self) -> int:
        raw = self.values.get("min_string_length", 4)
        return int(raw) if isinstance(raw, (int, str)) else 4

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> StaticAnalysisConfig:
        merged: dict[str, Any] = dict(STATIC_DEFAULTS)
        sub = cfg.get("static", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_static_config(repo_root: Path | None = None) -> StaticAnalysisConfig:
    """Load static-analysis configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return StaticAnalysisConfig.from_eng_config(load_config(root))
