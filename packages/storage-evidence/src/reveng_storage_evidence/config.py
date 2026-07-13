"""Storage-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the storage-owned surface from the
``storage`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.storage]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["StorageConfig", "load_storage_config", "STORAGE_DEFAULTS"]

STORAGE_DEFAULTS: dict[str, Any] = {
    # Whether the manager validates a repository before serializing (always true
    # in this phase; present so later phases can extend without a new mechanism).
    "validate_before_serialize": True,
}


@dataclass
class StorageConfig:
    """Typed view over storage-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(STORAGE_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> StorageConfig:
        merged: dict[str, Any] = dict(STORAGE_DEFAULTS)
        sub = cfg.get("storage", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_storage_config(repo_root: Path | None = None) -> StorageConfig:
    """Load storage configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return StorageConfig.from_eng_config(load_config(root))
