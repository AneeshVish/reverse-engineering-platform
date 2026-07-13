"""Construction helper for the storage manager."""

from __future__ import annotations

from .config import StorageConfig, load_storage_config
from .manager import StorageManager

__all__ = ["build_storage_manager"]


def build_storage_manager(config: StorageConfig | None = None) -> StorageManager:
    """Construct a ``StorageManager`` with resolved configuration."""

    return StorageManager(config=config or load_storage_config())
