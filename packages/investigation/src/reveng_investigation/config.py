"""Investigation-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the investigation-owned surface from
the ``investigation`` sub-table of ``[tool.reveng]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["InvestigationConfig", "load_investigation_config", "INVESTIGATION_DEFAULTS"]

INVESTIGATION_DEFAULTS: dict[str, Any] = {
    # Whether the builder validates a case before returning it (always true in
    # this phase; present so later phases can extend without a new mechanism).
    "validate_on_build": True,
}


@dataclass
class InvestigationConfig:
    """Typed view over investigation-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(INVESTIGATION_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> InvestigationConfig:
        merged: dict[str, Any] = dict(INVESTIGATION_DEFAULTS)
        sub = cfg.get("investigation", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_investigation_config(repo_root: Path | None = None) -> InvestigationConfig:
    """Load investigation configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return InvestigationConfig.from_eng_config(load_config(root))
