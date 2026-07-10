"""Substrate-owned configuration access.

Reuses the engineering configuration loader (``reveng_config.load_config``)
rather than introducing a competing mechanism. ``SubstrateConfig`` exposes only
the substrate-owned configuration surface, read from the ``substrate`` sub-table
of ``[tool.reveng]`` (i.e. ``[tool.reveng.substrate]``) with defaults applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

from .errors import ConfigError

__all__ = ["SubstrateConfig", "load_substrate_config", "SUBSTRATE_DEFAULTS"]

SUBSTRATE_DEFAULTS: dict[str, Any] = {
    # Whether component initialization failures should surface as lifecycle
    # errors (always true in this phase; present so later phases can extend
    # behavior additively without a new config mechanism).
    "strict_initialization": True,
    # Default health-check evaluation policy marker.
    "health_include_unknown": True,
}


@dataclass
class SubstrateConfig:
    """Typed view over substrate-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(SUBSTRATE_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.values.get(key, default)
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in {"1", "true", "yes", "on"}
        raise ConfigError("expected boolean config value", key=key, value=repr(raw))

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> SubstrateConfig:
        merged: dict[str, Any] = dict(SUBSTRATE_DEFAULTS)
        sub = cfg.get("substrate", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_substrate_config(repo_root: Path | None = None) -> SubstrateConfig:
    """Load substrate configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return SubstrateConfig.from_eng_config(load_config(root))
