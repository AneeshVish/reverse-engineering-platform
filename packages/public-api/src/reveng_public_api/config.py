"""Public API-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the public-api-owned surface from
the ``public_api`` sub-table of ``[tool.reveng]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["PublicApiConfig", "load_public_api_config", "PUBLIC_API_DEFAULTS"]

PUBLIC_API_DEFAULTS: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8000,
    # Maximum accepted upload size, in bytes (100 MiB).
    "max_upload_bytes": 100 * 1024 * 1024,
    # Worker threads in the job manager's background execution pool.
    "job_pool_size": 4,
}


@dataclass
class PublicApiConfig:
    """Typed view over public-api-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(PUBLIC_API_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> PublicApiConfig:
        merged: dict[str, Any] = dict(PUBLIC_API_DEFAULTS)
        sub = cfg.get("public_api", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_public_api_config(repo_root: Path | None = None) -> PublicApiConfig:
    """Load public-api configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return PublicApiConfig.from_eng_config(load_config(root))
