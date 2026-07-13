"""Reporting-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the reporting-owned surface from the
``reporting`` sub-table of ``[tool.reveng]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["ReportingConfig", "load_reporting_config", "REPORTING_DEFAULTS"]

REPORTING_DEFAULTS: dict[str, Any] = {
    # The template used when a caller does not specify one.
    "default_template": "executive_summary",
}


@dataclass
class ReportingConfig:
    """Typed view over reporting-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(REPORTING_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def default_template(self) -> str:
        raw = self.values.get("default_template", "executive_summary")
        return str(raw)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> ReportingConfig:
        merged: dict[str, Any] = dict(REPORTING_DEFAULTS)
        sub = cfg.get("reporting", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_reporting_config(repo_root: Path | None = None) -> ReportingConfig:
    """Load reporting configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return ReportingConfig.from_eng_config(load_config(root))
